# sepolicy-inject

Injects allow rules into binary SELinux kernel policies.

## Usage

```
Single rule:    sepolicy-inject -s <source> -t <target> -c <class> -p <perms> [-P policy] [-o output] [-l]
Multiple rules: sepolicy-inject -f <rules_file> [-P policy] [-o output] [-l]
Permissive:     sepolicy-inject -Z <type> [-P policy] [-o output] [-l]
Non-permissive: sepolicy-inject -z <type> [-P policy] [-o output] [-l]
```

Options:

- `-s <source>` — source type
- `-t <target>` — target type
- `-c <class>` — object class
- `-p <perms>` — comma-separated permissions
- `-f <rules_file>` — file with multiple rules (one per line)
- `-Z <type>` — mark type as permissive
- `-z <type>` — mark type as non-permissive
- `-P <policy>` — input binary policy (default: `/sys/fs/selinux/policy`)
- `-o <output>` — output binary policy (defaults to input policy)
- `-l` — load the modified policy into the kernel instead of writing a file

### Rules file format

One rule per line:

```
source target class perm1,perm2,...
# comments start with #
```

Example:

```
shell system file read
shell system dir search,open
```

## Examples

### Injecting a single rule

```
$ ./sepolicy-inject -s shell -t system -c file -p read -P sepolicy -o sepolicy2
libsepol.policydb_index_others: security:  1 users, 2 roles, 518 types, 14 bools
libsepol.policydb_index_others: security: 1 sens, 1024 cats
libsepol.policydb_index_others: security:  84 classes, 4539 rules, 162 cond rules

$ sesearch -A -s shell -t system -c file sepolicy
Found 1 semantic av rules:
   allow appdomain domain : file { ioctl read getattr lock open } ;

$ sesearch -A -s shell -t system -c file sepolicy2
Found 2 semantic av rules:
   allow shell system : file read ;
   allow appdomain domain : file { ioctl read getattr lock open } ;
```

Note: source/target types that do not exist yet are created automatically (and added to the `domain` attribute).

### Injecting multiple rules from a file

```
$ ./sepolicy-inject -f rules.txt -P sepolicy -o sepolicy2
Loaded 2 rules
Applying rule 1/2: shell -> system : file { read }
Applying rule 2/2: shell -> system : dir { search,open }
Policy with all rules saved to sepolicy2
```

### Injecting a permissive domain

```
$ ./sepolicy-inject -Z shell -P sepolicy -o sepolicy2

$ seinfo sepolicy | grep Permissive
   Permissives:         0    Polcap:              2

$ seinfo sepolicy2 | grep Permissive
   Permissives:         1    Polcap:              2
```

### Changing a permissive domain to non-permissive

```
$ ./sepolicy-inject -z shell -P sepolicy -o sepolicy2
```

### Loading the result directly into the kernel

```
$ ./sepolicy-inject -f rules.txt -l
All rules applied and loaded into kernel successfully
```

## TODO

- Remove rules
- Use attributes as source/target in rules
