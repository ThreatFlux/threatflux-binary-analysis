#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Global variables
int global_counter = 0;
char global_buffer[256] = "ThreatFlux Binary Analysis Test";

// Function prototypes
void print_banner(void);
int calculate_fibonacci(int n);
void process_data(const char* input);
void vulnerable_function(char* user_input);

// Main function
int main(int argc, char* argv[]) {
    print_banner();
    
    printf("Program started with %d arguments\n", argc);
    
    // Test basic arithmetic
    int fib_result = calculate_fibonacci(10);
    printf("Fibonacci(10) = %d\n", fib_result);
    
    // Test string processing
    process_data("Sample input data for analysis");
    
    // Simulate some system calls
    printf("Process ID: %d\n", getpid());
    
    // Test with user input if provided
    if (argc > 1) {
        printf("Processing argument: %s\n", argv[1]);
        vulnerable_function(argv[1]);
    }
    
    printf("Analysis complete. Global counter: %d\n", global_counter);
    return 0;
}

void print_banner(void) {
    printf("========================================\n");
    printf("  ThreatFlux Binary Analysis Test\n");
    printf("  Version 1.0.0\n");
    printf("  Test Binary for Static Analysis\n");
    printf("========================================\n");
}

int calculate_fibonacci(int n) {
    global_counter++;
    if (n <= 1) {
        return n;
    }
    return calculate_fibonacci(n - 1) + calculate_fibonacci(n - 2);
}

void process_data(const char* input) {
    char local_buffer[128];
    global_counter++;
    
    printf("Processing: %s\n", input);
    strncpy(local_buffer, input, sizeof(local_buffer) - 1);
    local_buffer[sizeof(local_buffer) - 1] = '\0';
    
    // Simulate some data processing
    for (int i = 0; local_buffer[i]; i++) {
        if (local_buffer[i] >= 'a' && local_buffer[i] <= 'z') {
            local_buffer[i] = local_buffer[i] - 'a' + 'A';
        }
    }
    
    printf("Processed result: %s\n", local_buffer);
}

// Intentionally vulnerable function for testing security analysis
void vulnerable_function(char* user_input) {
    char stack_buffer[64];
    global_counter++;
    
    printf("Processing user input...\n");
    
    // Potential buffer overflow vulnerability
    strcpy(stack_buffer, user_input);
    
    printf("User data: %s\n", stack_buffer);
    
    // Simulate some risky operations
    if (strstr(user_input, "admin") != NULL) {
        printf("Admin access detected!\n");
    }
    
    if (strstr(user_input, "debug") != NULL) {
        printf("Debug mode enabled\n");
        system("echo 'Debug information'");
    }
}