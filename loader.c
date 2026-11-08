#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <signal.h>

static volatile sig_atomic_t running = 1;
void sig_handler(int sig) { running = 0; }

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "Usage: %s <target_pid>\n", argv[0]); return 1; }

    __u32 target_pid = atoi(argv[1]);
    struct bpf_object *obj = bpf_object__open_file("anticheat.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "open failed\n"); return 1; }

    struct bpf_map *rodata = bpf_object__find_map_by_name(obj, ".rodata");
    if (rodata) bpf_map__set_initial_value(rodata, &target_pid, sizeof(target_pid));

    if (bpf_object__load(obj)) { fprintf(stderr, "load failed\n"); return 1; }
    
    struct bpf_program *p1 = bpf_object__find_program_by_name(obj, "guard_file_open");
    struct bpf_program *p2 = bpf_object__find_program_by_name(obj, "guard_ptrace");
    if (!p1 || !p2) { fprintf(stderr, "prog not found\n"); return 1; }

    struct bpf_link *l1 = bpf_program__attach_lsm(p1);
    struct bpf_link *l2 = bpf_program__attach_lsm(p2);
    if (!l1 || !l2) { fprintf(stderr, "attach failed\n"); return 1; }

    printf("[*] Защита PID %u: /proc/pid/mem + ptrace заблокированы\n", target_pid);
    signal(SIGINT, sig_handler);
    while (running) sleep(1);

    bpf_link__destroy(l1);
    bpf_link__destroy(l2);
    bpf_object__close(obj);
    return 0;
}