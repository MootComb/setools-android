#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sepol/debug.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/avrule_block.h>
#include <sepol/policydb/conditional.h>

// Kind of a parsed rule line.
typedef enum {
    RULE_ALLOW = 0,   // allow statement -> AVTAB_ALLOWED
    RULE_DONTAUDIT,   // dontaudit statement -> AVTAB_AUDITDENY
    RULE_PERMISSIVE,  // permissive <type> -> set bit in permissive_map
    RULE_ENFORCE      // enforce <type>    -> clear bit in permissive_map
} rule_kind_t;

// One parsed rule. target/class/perms may be NULL for permissive/enforce.
typedef struct {
    rule_kind_t kind;
    char *source;
    char *target;
    char *class;
    char *perms;
} selinux_rule_t;

// Dynamic array of parsed rules.
typedef struct {
    selinux_rule_t *rules;
    int count;
    int capacity;
} rule_list_t;

rule_list_t rule_list = {NULL, 0, 0};

// Reverse map: class value -> class name.
// In this libsepol version the class name lives in the hashtab key of
// policydb->p_classes.table, not in symtab_datum. We build the map once and
// keep borrowed pointers to the keys (owned by the policydb).
static const char **class_names = NULL;
static uint32_t class_names_nprim = 0;

typedef struct {
    policydb_t *policy;
    const char **names;
} class_names_ctx_t;

static int class_names_cb(hashtab_key_t key, hashtab_datum_t datum, void *ptr) {
    class_names_ctx_t *ctx = ptr;
    class_datum_t *cls = (class_datum_t *)datum;
    if (!cls || cls->s.value == 0 || cls->s.value > ctx->policy->p_classes.nprim)
        return 0;
    ctx->names[cls->s.value - 1] = (const char *)key;
    return 0;
}

// Build (once) the class value -> name map. Returns 0 on success.
static int build_class_names(policydb_t *policy) {
    if (class_names && class_names_nprim == policy->p_classes.nprim)
        return 0;

    free(class_names);
    class_names = calloc(policy->p_classes.nprim, sizeof(*class_names));
    if (!class_names) return 1;
    class_names_nprim = policy->p_classes.nprim;

    class_names_ctx_t ctx = { .policy = policy, .names = class_names };
    hashtab_map(policy->p_classes.table, class_names_cb, &ctx);
    return 0;
}

// Return the class name, or "?" if the map is not built or the value is bad.
static const char *class_name(class_datum_t *cls) {
    if (!cls || cls->s.value == 0 ||
        cls->s.value > class_names_nprim || !class_names)
        return "?";
    const char *n = class_names[cls->s.value - 1];
    return n ? n : "?";
}

void usage(char *arg0) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  Single rule: %s -s <source> -t <target> -c <class> -p <perms> [-P policy] [-o output] [-l]\n", arg0);
    fprintf(stderr, "  Multiple rules: %s -f <rules_file> [-P policy] [-o output] [-l]\n", arg0);
    fprintf(stderr, "  Allow-all: %s -a <domain> [-P policy] [-o output] [-l]\n", arg0);
    fprintf(stderr, "  Permissive: %s -Z <type> [-P policy] [-o output] [-l]\n", arg0);
    fprintf(stderr, "  Non-permissive: %s -z <type> [-P policy] [-o output] [-l]\n", arg0);
    fprintf(stderr, "\nRules file format (one per line):\n");
    fprintf(stderr, "  Bare:        source target class perm1,perm2,...\n");
    fprintf(stderr, "  sepolicy:    allow|dontaudit source target class perm1,perm2,...\n");
    fprintf(stderr, "  permissive:  permissive|enforce type\n");
    fprintf(stderr, "  Wildcards:   * is allowed for target, class and perms\n");
    fprintf(stderr, "  Permissions may be wrapped in braces: { read write } or {read,write}\n");
    fprintf(stderr, "  # comments start with #\n");
    exit(1);
}

// malloc wrapper that exits on out of memory.
void *cmalloc(size_t s) {
    void *t = malloc(s);
    if (t == NULL) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }
    return t;
}

// Strip trailing spaces and tabs in place.
static void strip_trailing(char *s) {
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
}

// Return a malloc'd copy of the permission string with braces removed
// and surrounding whitespace trimmed. Caller must free the result.
// Examples: "{search}" -> "search", "{ * }" -> "*", "{ read, write }" -> "read, write"
static char *strip_braces(const char *p) {
    if (!p) return NULL;
    char *copy = strdup(p);
    if (!copy) return NULL;

    // Remove all braces in place.
    char *write_ptr = copy;
    for (char *read_ptr = copy; *read_ptr; read_ptr++) {
        if (*read_ptr == '{' || *read_ptr == '}') continue;
        *write_ptr++ = *read_ptr;
    }
    *write_ptr = 0;

    // Trim leading whitespace.
    char *start = copy;
    while (*start == ' ' || *start == '\t') start++;

    // Trim trailing whitespace.
    char *end = start + strlen(start);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) *--end = 0;

    // Move trimmed content to the beginning of the buffer.
    if (start != copy) memmove(copy, start, end - start + 1);

    return copy;
}

// Append one parsed rule to the global list. Duplicates strings.
// Braces are stripped from the permission string before storing.
void add_to_rule_list(rule_kind_t kind, const char *source, const char *target,
                      const char *class, const char *perms) {
    if (rule_list.count >= rule_list.capacity) {
        rule_list.capacity = rule_list.capacity ? rule_list.capacity * 2 : 16;
        rule_list.rules = realloc(rule_list.rules,
                                  rule_list.capacity * sizeof(selinux_rule_t));
        if (!rule_list.rules) {
            fprintf(stderr, "Out of memory\n");
            exit(1);
        }
    }
    selinux_rule_t *rule = &rule_list.rules[rule_list.count++];
    rule->kind   = kind;
    rule->source = strdup(source);
    rule->target = target ? strdup(target) : NULL;
    rule->class  = class  ? strdup(class)  : NULL;
    rule->perms  = strip_braces(perms);
    if (!rule->source || (target && !rule->target) ||
        (class && !rule->class) || (perms && !rule->perms)) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }
}

// Parse a rules file. Supports these line formats:
//   bare:       source target class perms
//   allow:      allow     source target class perms
//   dontaudit:  dontaudit source target class perms
//   permissive: permissive type
//   enforce:    enforce type
// Permissions may be separated by commas or spaces, and may be wrapped
// in braces, for example: { read, write } or {search} or read,write.
// Lines starting with '#' (including '##') and empty lines are skipped.
int load_rules_file(char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open rules file: %s\n", filename);
        return 1;
    }

    char line[2048];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        // Strip CR/LF.
        line[strcspn(line, "\r\n")] = 0;

        // Skip leading whitespace.
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        // Skip empty lines and comments.
        if (*p == 0 || *p == '#')
            continue;

        // Read the first token; it may be a keyword or a source type.
        char kw[64] = {0};
        if (sscanf(p, "%63s", kw) != 1) continue;

        if (strcmp(kw, "allow") == 0 || strcmp(kw, "dontaudit") == 0) {
            // Keyword-prefixed form: allow|dontaudit S T C P
            char s[512], t[512], c[512], perms[1024];
            int n = sscanf(p, "%*s %511s %511s %511s %1023[^\n]",
                           s, t, c, perms);
            if (n != 4) {
                fprintf(stderr, "Parse error line %d: %s\n", line_num, p);
                continue;
            }
            strip_trailing(perms);
            rule_kind_t k = (strcmp(kw, "allow") == 0) ? RULE_ALLOW : RULE_DONTAUDIT;
            add_to_rule_list(k, s, t, c, perms);
            printf("Rule %d: %s %s -> %s : %s { %s }\n", line_num, kw, s, t, c, perms);

        } else if (strcmp(kw, "permissive") == 0 || strcmp(kw, "enforce") == 0) {
            // permissive|enforce TYPE
            char s[512];
            if (sscanf(p, "%*s %511s", s) != 1) {
                fprintf(stderr, "Parse error line %d: %s\n", line_num, p);
                continue;
            }
            rule_kind_t k = (strcmp(kw, "permissive") == 0) ? RULE_PERMISSIVE : RULE_ENFORCE;
            add_to_rule_list(k, s, NULL, NULL, NULL);
            printf("Rule %d: %s %s\n", line_num, kw, s);

        } else {
            // Fallback: bare form S T C P (backward compatibility).
            char s[512], t[512], c[512], perms[1024];
            int n = sscanf(p, "%511s %511s %511s %1023[^\n]", s, t, c, perms);
            if (n == 4) {
                strip_trailing(perms);
                add_to_rule_list(RULE_ALLOW, s, t, c, perms);
                printf("Rule %d: allow %s -> %s : %s { %s }\n", line_num, s, t, c, perms);
            } else {
                fprintf(stderr, "Parse error line %d: %s\n", line_num, p);
            }
        }
    }

    fclose(fp);
    printf("Loaded %d rules\n", rule_list.count);
    return 0;
}

// Set one bit in the "domain" attribute (used by create_domain).
void set_attr(char *type, policydb_t *policy, int value) {
    type_datum_t *attr = hashtab_search(policy->p_types.table, type);
    if (!attr) {
        fprintf(stderr, "%s not present in the policy\n", type);
        exit(1);
    }
    if (attr->flavor != TYPE_ATTRIB) {
        fprintf(stderr, "%s is not an attribute\n", type);
        exit(1);
    }
    if (ebitmap_set_bit(&attr->types, value - 1, 1)) {
        fprintf(stderr, "error setting attribute: %s\n", type);
        exit(1);
    }
}

// Create a new TYPE_TYPE domain if it does not exist.
// Returns its value or 0 on failure (exits on hard errors).
int create_domain(char *d, policydb_t *policy) {
    symtab_datum_t *src = hashtab_search(policy->p_types.table, d);
    if (src)
        return src->value;

    type_datum_t *typdatum = (type_datum_t *) cmalloc(sizeof(type_datum_t));
    type_datum_init(typdatum);
    typdatum->primary = 1;
    typdatum->flavor = TYPE_TYPE;

    uint32_t value = 0;
    char *type = strdup(d);
    if (type == NULL) exit(1);

    int r = symtab_insert(policy, SYM_TYPES, type, typdatum, SCOPE_DECL, 1, &value);
    if (r) {
        fprintf(stderr, "Failed to insert type into symtab\n");
        exit(1);
    }
    typdatum->s.value = value;

    // Mark it as declared in the global scope.
    if (ebitmap_set_bit(&policy->global->branch_list->declared.scope[SYM_TYPES],
                        value - 1, 1)) {
        exit(1);
    }

    // Grow type_attr_map / attr_type_map and init the new slot.
    policy->type_attr_map = realloc(policy->type_attr_map,
                                    sizeof(ebitmap_t) * policy->p_types.nprim);
    policy->attr_type_map = realloc(policy->attr_type_map,
                                    sizeof(ebitmap_t) * policy->p_types.nprim);
    ebitmap_init(&policy->type_attr_map[value - 1]);
    ebitmap_init(&policy->attr_type_map[value - 1]);
    ebitmap_set_bit(&policy->type_attr_map[value - 1], value - 1, 1);

    // Allow every role to use this new type.
    unsigned i;
    for (i = 0; i < policy->p_roles.nprim; ++i) {
        ebitmap_set_bit(&policy->role_val_to_struct[i]->types.negset, value - 1, 0);
        ebitmap_set_bit(&policy->role_val_to_struct[i]->types.types, value - 1, 1);
        type_set_expand(&policy->role_val_to_struct[i]->types,
                        &policy->role_val_to_struct[i]->cache, policy, 0);
    }

    src = hashtab_search(policy->p_types.table, d);
    if (!src) {
        fprintf(stderr, "creating %s failed\n", d);
        exit(1);
    }

    // Rebuild indexes after adding a new type.
    extern int policydb_index_decls(policydb_t * p);
    if (policydb_index_decls(policy)) {
        exit(1);
    }

    // The new type is also a domain.
    set_attr("domain", policy, value);
    return value;
}

// Convert a permission list into a bitmask.
// Accepts: "read,write", "read write", "{ read write }", "{read,write}", "*"
// Returns 0 on success, non-zero on error.
static int perms_to_mask(class_datum_t *cls, const char *p, uint32_t *out) {
    uint32_t data = 0;
    char *copy = strdup(p);
    if (!copy) return 1;

    // Strip braces anywhere in the string, in place.
    char *write_ptr = copy;
    for (char *read_ptr = copy; *read_ptr; read_ptr++) {
        if (*read_ptr == '{' || *read_ptr == '}') continue;
        *write_ptr++ = *read_ptr;
    }
    *write_ptr = 0;

    // Trim leading whitespace.
    char *start = copy;
    while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r') start++;

    // Trim trailing whitespace.
    char *end = start + strlen(start);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t' ||
                           end[-1] == '\n' || end[-1] == '\r')) {
        *--end = 0;
    }

    if (*start == 0) {
        free(copy);
        *out = 0;
        return 0;
    }

    char *save = NULL;
    char *token = strtok_r(start, ", \t", &save);
    while (token) {
        perm_datum_t *perm = hashtab_search(cls->permissions.table, token);
        if (!perm && cls->comdatum)
            perm = hashtab_search(cls->comdatum->permissions.table, token);
        if (!perm) {
            fprintf(stderr, "perm %s does not exist in class %s\n",
                    token, class_name(cls));
            free(copy);
            return 2;
        }
        data |= 1U << (perm->s.value - 1);
        token = strtok_r(NULL, ", \t", &save);
    }
    free(copy);
    *out = data;
    return 0;
}

// Mask with all permissions of a class (own + common).
// Limited to 32 bits by avtab_datum_t.data.
static uint32_t all_perms_mask(class_datum_t *cls) {
    unsigned total = cls->permissions.nprim;
    if (cls->comdatum) total += cls->comdatum->permissions.nprim;
    if (total == 0) return 0;
    if (total > 32) {
        fprintf(stderr, "warning: class %s has %u perms (mask truncated to 32)\n",
                class_name(cls), total);
        total = 32;
    }
    if (total == 32) return 0xFFFFFFFFu;
    return (1u << total) - 1u;
}

// Insert or merge one avtab entry.
// For dontaudit we store the inverse mask, matching sepol semantics.
static int apply_one_av(policydb_t *policy,
                        uint32_t s_val, uint32_t t_val, uint32_t c_val,
                        uint32_t data, int is_dontaudit) {
    avtab_key_t key;
    key.source_type = s_val;
    key.target_type = t_val;
    key.target_class = c_val;
    key.specified   = is_dontaudit ? AVTAB_AUDITDENY : AVTAB_ALLOWED;

    avtab_datum_t *av = avtab_search(&policy->te_avtab, &key);
    if (!av) {
        av = cmalloc(sizeof(*av));
        av->data = is_dontaudit ? ~data : data;
        if (avtab_insert(&policy->te_avtab, &key, av)) {
            fprintf(stderr, "Error inserting into avtab\n");
            return 1;
        }
    } else {
        if (is_dontaudit) av->data &= ~data;
        else              av->data |=  data;
    }
    return 0;
}

// Context passed to walk_types_cb.
typedef struct {
    policydb_t *policy;
    uint32_t s_val;
    int is_dontaudit;
    uint32_t c_val;      // 0 = any class
    const char *p_pat;   // NULL or "*" = all perms
    int errors;
} walk_ctx_t;

// Callback used when target is "*": iterate all concrete types.
// For each type, iterate all matching classes and insert the rule.
static int walk_types_cb(hashtab_key_t key, hashtab_datum_t datum, void *ptr) {
    (void)key;
    walk_ctx_t *ctx = ptr;
    type_datum_t *td = (type_datum_t *) datum;
    if (td->flavor != TYPE_TYPE) return 0;   // skip attributes
    if (td->s.value == 0) return 0;

    policydb_t *pol = ctx->policy;
    uint32_t t_val = td->s.value;

    for (unsigned i = 0; i < pol->p_classes.nprim; i++) {
        class_datum_t *cls = pol->class_val_to_struct[i];
        if (!cls) continue;

        // Filter by class value (0 = any).
        if (ctx->c_val != 0 && cls->s.value != ctx->c_val)
            continue;

        // Resolve permission mask (or all perms for "*").
        uint32_t mask;
        if (ctx->p_pat && strcmp(ctx->p_pat, "*") == 0) {
            mask = all_perms_mask(cls);
        } else if (perms_to_mask(cls, ctx->p_pat, &mask)) {
            ctx->errors++;
            continue;
        }

        if (apply_one_av(pol, ctx->s_val, t_val, cls->s.value,
                         mask, ctx->is_dontaudit))
            ctx->errors++;
    }
    return 0;
}

// Add an allow or dontaudit rule.
// '*' is supported for target, class and perms.
int add_rule_ex(const char *s, const char *t, const char *c, const char *p,
                policydb_t *policy, int is_dontaudit) {
    if (build_class_names(policy)) {
        fprintf(stderr, "Out of memory building class name map\n");
        return 1;
    }

    type_datum_t *src = hashtab_search(policy->p_types.table, (char *)s);
    if (!src) {
        fprintf(stderr, "source type %s does not exist\n", s);
        return 2;
    }

    int target_wild = (strcmp(t, "*") == 0);
    int class_wild  = (strcmp(c, "*") == 0);
    int perms_wild  = (strcmp(p, "*") == 0);

    // Resolve concrete target type once (if not wildcard).
    type_datum_t *tgt = NULL;
    if (!target_wild) {
        tgt = hashtab_search(policy->p_types.table, (char *)t);
        if (!tgt) {
            fprintf(stderr, "target type %s does not exist\n", t);
            return 2;
        }
    }

    // Resolve concrete class once (if not wildcard).
    class_datum_t *cls = NULL;
    if (!class_wild) {
        cls = hashtab_search(policy->p_classes.table, (char *)c);
        if (!cls) {
            fprintf(stderr, "class %s does not exist\n", c);
            return 2;
        }
    }

    // Case 1: concrete target, concrete class, concrete perms.
    if (!target_wild && !class_wild && !perms_wild) {
        uint32_t mask;
        if (perms_to_mask(cls, p, &mask)) return 2;
        return apply_one_av(policy, src->s.value, tgt->s.value,
                            cls->s.value, mask, is_dontaudit);
    }

    // Case 2: concrete target, concrete class, wildcard perms.
    if (!target_wild && !class_wild && perms_wild) {
        return apply_one_av(policy, src->s.value, tgt->s.value,
                            cls->s.value, all_perms_mask(cls), is_dontaudit);
    }

    // Case 3: concrete target, wildcard class: iterate all classes.
    if (!target_wild && class_wild) {
        int errs = 0;
        for (unsigned i = 0; i < policy->p_classes.nprim; i++) {
            class_datum_t *ci = policy->class_val_to_struct[i];
            if (!ci) continue;
            uint32_t mask;
            if (perms_wild) mask = all_perms_mask(ci);
            else if (perms_to_mask(ci, p, &mask)) { errs++; continue; }
            if (apply_one_av(policy, src->s.value, tgt->s.value,
                             ci->s.value, mask, is_dontaudit))
                errs++;
        }
        return errs ? 1 : 0;
    }

    // Case 4: wildcard target: iterate all concrete types.
    walk_ctx_t ctx = { .policy = policy, .s_val = src->s.value,
                       .is_dontaudit = is_dontaudit,
                       .c_val = cls ? cls->s.value : 0,
                       .p_pat = p, .errors = 0 };
    hashtab_map(policy->p_types.table, walk_types_cb, &ctx);
    return ctx.errors ? 1 : 0;
}

// Backward-compatible wrapper for allow-only.
int add_rule(char *s, char *t, char *c, char *p, policydb_t *policy) {
    return add_rule_ex(s, t, c, p, policy, 0);
}

// Apply all parsed rules in order.
// Creates missing source/target types on demand.
int apply_all_rules(policydb_t *policy) {
    int errors = 0;

    for (int i = 0; i < rule_list.count; i++) {
        selinux_rule_t *r = &rule_list.rules[i];

        if (r->kind == RULE_PERMISSIVE || r->kind == RULE_ENFORCE) {
            // Toggle permissive bit for the type.
            type_datum_t *type = hashtab_search(policy->p_types.table, r->source);
            if (!type) {
                fprintf(stderr, "type %s does not exist\n", r->source);
                errors++;
                continue;
            }
            int val = (r->kind == RULE_PERMISSIVE) ? 1 : 0;
            if (ebitmap_set_bit(&policy->permissive_map, type->s.value, val)) {
                fprintf(stderr, "Could not set bit in permissive map for %s\n", r->source);
                errors++;
            } else {
                printf("%s %s\n",
                       r->kind == RULE_PERMISSIVE ? "permissive" : "enforce",
                       r->source);
            }
            continue;
        }

        // allow / dontaudit: create missing types first.
        type_datum_t *type = hashtab_search(policy->p_types.table, r->source);
        if (!type) {
            printf("Creating source type: %s\n", r->source);
            create_domain(r->source, policy);
        }
        if (r->target && strcmp(r->target, "*") != 0) {
            type = hashtab_search(policy->p_types.table, r->target);
            if (!type) {
                printf("Creating target type: %s\n", r->target);
                create_domain(r->target, policy);
            }
        }

        int ret = add_rule_ex(r->source, r->target, r->class, r->perms,
                              policy, r->kind == RULE_DONTAUDIT);
        if (ret) {
            fprintf(stderr, "Failed rule %d\n", i + 1);
            errors++;
        } else {
            printf("Applied %s %s -> %s : %s { %s }\n",
                   r->kind == RULE_DONTAUDIT ? "dontaudit" : "allow",
                   r->source, r->target, r->class, r->perms);
        }
    }

    return errors;
}

// Load a binary policy from file into memory-mapped policydb.
int load_policy(char *filename, policydb_t *policydb, struct policy_file *pf) {
    int fd;
    struct stat sb;
    void *map;
    int ret;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Can't open '%s':  %s\n", filename, strerror(errno));
        return 1;
    }
    if (fstat(fd, &sb) < 0) {
        fprintf(stderr, "Can't stat '%s':  %s\n", filename, strerror(errno));
        close(fd);
        return 1;
    }
    map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "Can't mmap '%s':  %s\n", filename, strerror(errno));
        close(fd);
        return 1;
    }

    policy_file_init(pf);
    pf->type = PF_USE_MEMORY;
    pf->data = map;
    pf->len = sb.st_size;
    if (policydb_init(policydb)) {
        fprintf(stderr, "policydb_init: Out of memory!\n");
        munmap(map, sb.st_size);
        close(fd);
        return 1;
    }
    ret = policydb_read(policydb, pf, 1);
    if (ret) {
        fprintf(stderr, "error(s) encountered while parsing configuration\n");
        munmap(map, sb.st_size);
        close(fd);
        return 1;
    }

    munmap(map, sb.st_size);
    close(fd);
    return 0;
}

// Serialize policydb to image and write it to the kernel.
int load_policy_into_kernel(policydb_t *policydb) {
    char *filename = "/sys/fs/selinux/load";
    int fd, ret;
    void *data = NULL;
    size_t len;

    if (policydb_to_image(NULL, policydb, &data, &len)) {
        fprintf(stderr, "Could not convert policy to image\n");
        return 1;
    }

    fd = open(filename, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Can't open '%s':  %s\n", filename, strerror(errno));
        free(data);
        return 1;
    }

    ret = write(fd, data, len);
    close(fd);
    free(data);

    if (ret < 0) {
        fprintf(stderr, "Could not write policy to %s\n", filename);
        return 1;
    }

    printf("Policy loaded successfully (%zu bytes)\n", len);
    return 0;
}

// Selection modes for the main() switch.
#define SEL_ADD_RULE    1
#define SEL_PERMISSIVE  2
#define SEL_MULTI_RULE  3
#define SEL_ALLOW_ALL   4

int main(int argc, char **argv) {
    char *policy = NULL, *source = NULL, *target = NULL, *class = NULL, *outfile = NULL;
    char *perms = NULL, *rules_file = NULL;
    policydb_t policydb;
    struct policy_file pf, outpf;
    sidtab_t sidtab;
    int ch;
    FILE *fp;
    int load = 0;
    int permissive_value = 0;
    int typeval;
    type_datum_t *type;
    int selected = 0;

    struct option long_options[] = {
        {"source", required_argument, NULL, 's'},
        {"target", required_argument, NULL, 't'},
        {"class", required_argument, NULL, 'c'},
        {"perm", required_argument, NULL, 'p'},
        {"policy", required_argument, NULL, 'P'},
        {"output", required_argument, NULL, 'o'},
        {"permissive", required_argument, NULL, 'Z'},
        {"not-permissive", required_argument, NULL, 'z'},
        {"load", no_argument, NULL, 'l'},
        {"file", required_argument, NULL, 'f'},
        {"allow-all", required_argument, NULL, 'a'},
        {NULL, 0, NULL, 0}
    };

    while ((ch = getopt_long(argc, argv, "s:t:c:p:P:o:Z:z:lf:a:",
                             long_options, NULL)) != -1) {
        switch (ch) {
        case 's':
            if (selected && selected != SEL_ADD_RULE) usage(argv[0]);
            selected = SEL_ADD_RULE;
            source = optarg;
            break;
        case 't': target = optarg; break;
        case 'c': class  = optarg; break;
        case 'p': perms  = optarg; break;
        case 'P': policy = optarg; break;
        case 'o': outfile = optarg; break;
        case 'Z':
            if (selected) usage(argv[0]);
            selected = SEL_PERMISSIVE;
            source = optarg;
            permissive_value = 1;
            break;
        case 'z':
            if (selected) usage(argv[0]);
            selected = SEL_PERMISSIVE;
            source = optarg;
            permissive_value = 0;
            break;
        case 'l': load = 1; break;
        case 'f':
            if (selected) usage(argv[0]);
            selected = SEL_MULTI_RULE;
            rules_file = optarg;
            break;
        case 'a':
            if (selected) usage(argv[0]);
            selected = SEL_ALLOW_ALL;
            source = optarg;
            break;
        default:
            usage(argv[0]);
        }
    }

    // Validate required arguments for the chosen mode.
    if (!selected) usage(argv[0]);
    if (selected == SEL_ADD_RULE && (!source || !target || !class || !perms))
        usage(argv[0]);
    if (selected == SEL_MULTI_RULE && !rules_file)
        usage(argv[0]);
    if (selected == SEL_ALLOW_ALL && !source)
        usage(argv[0]);

    // Default outfile: same as input policy (in-place edit).
    if (!outfile && policy)
        outfile = policy;
    if (!policy)
        policy = "/sys/fs/selinux/policy";

    sepol_set_policydb(&policydb);
    sepol_set_sidtab(&sidtab);

    if (load_policy(policy, &policydb, &pf)) {
        fprintf(stderr, "Could not load policy\n");
        return 1;
    }

    if (policydb_load_isids(&policydb, &sidtab))
        return 1;

    if (selected == SEL_MULTI_RULE) {
        if (load_rules_file(rules_file)) {
            fprintf(stderr, "Failed to load rules file\n");
            return 1;
        }
        if (apply_all_rules(&policydb)) {
            fprintf(stderr, "Some rules failed to apply\n");
            return 1;
        }
    } else if (selected == SEL_ADD_RULE) {
        // Single rule via -s -t -c -p.
        type = hashtab_search(policydb.p_types.table, source);
        if (type == NULL) {
            fprintf(stderr, "type %s does not exist, creating\n", source);
            create_domain(source, &policydb);
        }
        if (add_rule(source, target, class, perms, &policydb)) {
            fprintf(stderr, "Could not add rule\n");
            return 1;
        }
    } else if (selected == SEL_PERMISSIVE) {
        // Toggle permissive bit for a single type.
        type = hashtab_search(policydb.p_types.table, source);
        if (!type) {
            fprintf(stderr, "type %s does not exist\n", source);
            return 1;
        }
        typeval = type->s.value;
        if (ebitmap_set_bit(&policydb.permissive_map, typeval, permissive_value)) {
            fprintf(stderr, "Could not set bit in permissive map\n");
            return 1;
        }
    } else if (selected == SEL_ALLOW_ALL) {
        // Allow everything for the domain, and suppress AVC noise.
        type = hashtab_search(policydb.p_types.table, source);
        if (!type) {
            fprintf(stderr, "type %s does not exist\n", source);
            return 1;
        }
        printf("Allow-all for domain %s (allow + dontaudit)\n", source);
        if (add_rule_ex(source, "*", "*", "*", &policydb, 0)) {
            fprintf(stderr, "allow-all failed\n");
            return 1;
        }
        if (add_rule_ex(source, "*", "*", "*", &policydb, 1)) {
            fprintf(stderr, "dontaudit-all failed\n");
            return 1;
        }
    }

    // Either load into kernel or write to file.
    if (load) {
        if (load_policy_into_kernel(&policydb)) {
            fprintf(stderr, "Could not load new policy into kernel\n");
            return 1;
        }
        printf("All rules applied and loaded into kernel successfully\n");
    } else if (outfile) {
        fp = fopen(outfile, "w");
        if (!fp) {
            fprintf(stderr, "Could not open outfile\n");
            return 1;
        }
        policy_file_init(&outpf);
        outpf.type = PF_USE_STDIO;
        outpf.fp = fp;
        if (policydb_write(&policydb, &outpf)) {
            fprintf(stderr, "Could not write policy\n");
            fclose(fp);
            return 1;
        }
        fclose(fp);
        printf("Policy with all rules saved to %s\n", outfile);
    }

    // Cleanup.
    if (rule_list.rules) {
        for (int i = 0; i < rule_list.count; i++) {
            free(rule_list.rules[i].source);
            free(rule_list.rules[i].target);
            free(rule_list.rules[i].class);
            free(rule_list.rules[i].perms);
        }
        free(rule_list.rules);
    }

    free(class_names);
    class_names = NULL;
    class_names_nprim = 0;

    policydb_destroy(&policydb);
    return 0;
}
