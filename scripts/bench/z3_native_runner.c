#include <stdio.h>
#include <string.h>

#include <z3.h>

static int z3_error = 0;

static void handle_error(Z3_context context, Z3_error_code code) {
    z3_error = (int)code;
    fprintf(stderr, "Z3 error: %s\n", Z3_get_error_msg(context, code));
}

static int print_version(void) {
    unsigned major = 0;
    unsigned minor = 0;
    unsigned build = 0;
    unsigned revision = 0;
    Z3_get_version(&major, &minor, &build, &revision);
    printf("Z3 version %u.%u.%u - 64 bit\n", major, minor, build);
    return 0;
}

static int set_supported_parameter(const char *argument) {
    if (strcmp(argument, "sat.euf=true") == 0) {
        Z3_global_param_set("sat.euf", "true");
        return 1;
    }
    if (strcmp(argument, "sat.euf=false") == 0) {
        Z3_global_param_set("sat.euf", "false");
        return 1;
    }

    fprintf(stderr, "unsupported Z3 parameter: %s\n", argument);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 &&
        (strcmp(argv[1], "-version") == 0 || strcmp(argv[1], "--version") == 0)) {
        return print_version();
    }
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s [sat.euf=true|sat.euf=false] FILE.smt2\n", argv[0]);
        return 64;
    }
    if (argc == 3 && !set_supported_parameter(argv[1])) {
        return 64;
    }

    const char *input_path = argv[argc - 1];

    Z3_config config = Z3_mk_config();
    Z3_context context = Z3_mk_context(config);
    Z3_del_config(config);
    Z3_set_error_handler(context, handle_error);

    Z3_symbol logic = Z3_mk_string_symbol(context, "QF_UF");
    Z3_solver solver = Z3_mk_solver_for_logic(context, logic);
    Z3_solver_inc_ref(context, solver);
    Z3_solver_from_file(context, solver, input_path);
    Z3_lbool result = z3_error ? Z3_L_UNDEF : Z3_solver_check(context, solver);

    int exit_code = z3_error ? 2 : 0;
    if (z3_error) {
        puts("error");
    } else if (result == Z3_L_TRUE) {
        puts("sat");
    } else if (result == Z3_L_FALSE) {
        puts("unsat");
    } else {
        puts("unknown");
        const char *reason = Z3_solver_get_reason_unknown(context, solver);
        if (reason && reason[0] != '\0') {
            fprintf(stderr, "reason: %s\n", reason);
        }
    }

    Z3_solver_dec_ref(context, solver);
    Z3_del_context(context);
    return exit_code;
}
