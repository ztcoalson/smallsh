#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

// Stores pid and terminating signal of a background process
struct bg_ps {
    int pid;
    // three states for signal:
    // -1: bg process is running 
    // -2: bg process has ended and been cleaned up (don't feel like removing elements from dynarray)
    // else: bg process has ended but needs to be cleaned up
    int signal;
};

// Array of background processes (with capacity and size because it is dynamic)
struct bg_ps* bgs = NULL;
int cap_bgs = 0;
int num_bgs = 0;

// holds pid of most recent foreground process
int fg_pid = 0;

// Determines whether foreground-only mode is in effect
int fg_only = 0;

// Contains all necessary components of a command
struct command {
    int num_cmds;   // Sum of initial command and subsequent arguments (not including input/output/background)
    char** cmds;    // char* array of commands
    int is_input;   // Did the user want to redirect input?
    char* input;    // File to take input from
    int is_output;  // Did the user want to redirect output?
    char* output;   // File to output to
    int background; // Should it be a background process?
};

// Reads input in from user
int get_input(char** input) {
    // Free input so user can enter new input
    if(*input)
        free(*input);
    
    // Account for a max input of 2048 (argument array is dynamic so need to account for max of 512 arguments)
    size_t max_length = 2048;
    size_t input_length;
    *input = (char*) calloc(max_length+1, sizeof(char));
    
    // Read in input with max length of 2048
    printf(": ");
    fflush(stdout);
    input_length = getline(input, &max_length, stdin);

    // Replace newline character with null terminator
    (*input)[input_length-1] = '\0';

    // returns 0 if entered command was to exit, 1 otherwise
    return strcmp(*input, "exit");
}

// Parse user input and return command struct equivalent
struct command get_cmds(char* input, int shell_pid) {
    // Initialize command struct (not sure if cmd = {0} would perform the correct initializations I need)
    struct command cmd;
    cmd.num_cmds = 0;
    cmd.cmds = NULL;
    cmd.is_input = 0;
    cmd.input = NULL;
    cmd.is_output = 0;
    cmd.output = NULL;
    cmd.background = 0;

    // Tokenize input
    char* saveptr;
    char* token = strtok_r(input, " ", &saveptr);
        
    // Loop while there is more to be parsed
    while(token)
    {   
        // Need to keep track of current token and next, hence using two
        char* curr_token = calloc(strlen(token)+1, sizeof(char));
        strcpy(curr_token, token);
        
        token = strtok_r(NULL, " ", &saveptr);

        // If last token in sequence is "&", set command as a background process
        if(!strcmp(curr_token, "&") && token == NULL) {
            cmd.background = 1;
        }
        // If user wants to redirect input, set is_input equal to true, tokenize next input which is the file name, and set input equal to the token
        else if(!strcmp(curr_token, "<")) {
            cmd.is_input = 1;
            cmd.input = calloc(strlen(token)+1, sizeof(char));
            strcpy(cmd.input, token);
            token = strtok_r(NULL, " ", &saveptr);
        }
        // If user wants to redirect output, set is_output equal to true, tokenize next input which is the file name, and set output equal to the token
        else if(!strcmp(curr_token, ">")) {
            cmd.is_output = 1;
            cmd.output = calloc(strlen(token)+1, sizeof(char));
            strcpy(cmd.output, token);
            token = strtok_r(NULL, " ", &saveptr);
        }
        // Final case is that input is an argument or the base command
        else {
            // Account for new cmd being added
            cmd.num_cmds++;
            
            // Allocate or resize cmds array
            if(cmd.num_cmds == 1) 
                cmd.cmds = malloc(cmd.num_cmds * sizeof(char*));
            else
                cmd.cmds = realloc(cmd.cmds, cmd.num_cmds * sizeof(char*));

            // Convert pid to str
            char* pid = calloc(15, sizeof(char));
            sprintf(pid, "%d", shell_pid);
            
            // Expand $$ into process id of shell

            // Stores new, (potentially) expanded command
            char* temp = calloc(1000, sizeof(char));
            
            for(int i = 0; i < strlen(curr_token); i++) {
                // If current and next index = $, concatenate shell pid and increment i
                if(i < strlen(curr_token)-1 && curr_token[i] == '$' && curr_token[i+1] == '$') {
                    strcat(temp, pid);
                    i++;
                }
                // Else, concatenate current character
                else {
                    char c = curr_token[i];
                    strncat(temp, &c, 1);
                }
            }

            // Copy current cmd over to cmds array
            cmd.cmds[cmd.num_cmds-1] = calloc(strlen(temp)+1, sizeof(char));
            strcpy(cmd.cmds[cmd.num_cmds-1], temp);

            free(pid);
            free(temp);
        }
        free(curr_token);
    }
    return cmd;
}

// Free all memory in cmds array
void free_cmd(struct command cmd) {
    if(cmd.input)
        free(cmd.input);
    if(cmd.output)
        free(cmd.output);
    if(cmd.cmds){
        for(int i = 0; i < cmd.num_cmds; i++)
            free(cmd.cmds[i]);
        free(cmd.cmds);
    }
}

void cd(struct command cmd) {
    // If just cd was entered, set cwd to HOME
    if(cmd.num_cmds == 1) {
        int result = chdir(getenv("HOME"));
        if(result == -1)
            printf("Invalid path\n");
    }
    // If cd has an arg, set cwd to that arg
    else {
        int result = chdir(cmd.cmds[1]);
        if(result == -1)
            printf("Invalid path\n");
    }
    fflush(stdout);
}

// Prints out status of last foreground process (exit value 0 if no foreground processes have been run)
void status(int last_status) {
    if(WIFEXITED(last_status))
        printf("exit value %d\n", WEXITSTATUS(last_status));
    else if(WTERMSIG(last_status))
        printf("terminated by signal %d\n", WTERMSIG(last_status));
    fflush(stdout);
}

// SIGNAL HANDLER: Handles sigint if called from child process (foreground only)
void sigint_child(int sig) {
    write(STDOUT_FILENO, "terminated by signal 2\n", 23);
}

// SIGNAL HANDLER: Handles sigchld
void cleanup_child(int sig) {
    int status;
    
    // Call waitpid to catch the recently ended child process
    pid_t pid = waitpid(-1, &status, WNOHANG);
    
    // return if child couldn't be caught
    if(pid == -1)
        return;
    // If child caught is a background process, update its status                         
    for(int i = 0; i < num_bgs; i++) {
        if(pid == bgs[i].pid) {
            bgs[i].signal = status;
            return;
        }
    }
}

// Execute a process in the background
void exec_bg(struct command cmd, struct sigaction sigtstp_action) {
    // Prepare file I/O for child process
    int input = -1;
    int output = -1;
    // Open file for input, or /dev/null if none was specified
    if(cmd.is_input)
        input = open(cmd.input, O_RDONLY);
    else 
        input = open("/dev/null", O_RDONLY);
    // Open file for output, or /dev/null if none was specified
    if(cmd.is_output)
        output = open(cmd.output, O_CREAT | O_WRONLY | O_TRUNC, 0664);
    else
        output = open("/dev/null", O_CREAT | O_WRONLY | O_TRUNC, 0664);

    // Variables for upcoming fork
    pid_t spawn_pid = -5;
	int child_pid;
    int child_signal;

    // Ignore sigtstp (sigint is already ignored because shell ignores it)
    sigtstp_action.sa_handler = SIG_IGN;
    sigaction(SIGTSTP, &sigtstp_action, NULL);

    // Create fork
    spawn_pid = fork();                  
    
    // Exit with status 1 if fork failed
	if (spawn_pid == -1) {
        exit(1);
    }
    // Child specific code
    else if(spawn_pid == 0) {
        // Redirect I/O to user specified files and/or /dev/null
        if(input == -1) {
            printf("cannot open %s for input\n", cmd.input);
            fflush(stdout);
            exit(1);
        }
        else {
            dup2(input, STDIN_FILENO);
        }
        if(output == -1) {
            printf("cannot open %s for output\n", cmd.output);
            fflush(stdout);
            exit(1);
        }
        else {
            dup2(output, STDOUT_FILENO);
        }

        // Build char array in form of char* arr[], as execvp expects that type
        char* args[cmd.num_cmds+1];
        for (int i = 0; i < cmd.num_cmds; i++)
        {
            args[i] = cmd.cmds[i];
        }
        args[cmd.num_cmds] = NULL;

        // Execute command
        int status = execvp(cmd.cmds[0], args);
        
        // If command failed, tell user and return exit status 1
        printf("%s: no such file or directory\n", cmd.cmds[0]);
        fflush(stdout);
        exit(1);
    }
    // Parent specific code
    else {
        // Provide pid of background process
        printf("background pid is %d\n", spawn_pid);
        fflush(stdout);

        // Handle reallocation of bg array
        num_bgs++;
        if(cap_bgs == 0) {
            bgs = malloc(sizeof(struct bg_ps) * 4);
            cap_bgs = 4;
        }
        else if(num_bgs == cap_bgs) {
            bgs = realloc(bgs, sizeof(struct bg_ps) * cap_bgs * 2);
            cap_bgs *= 2;
        }

        // Set pid and signal of bg process (-1 signifies it has not ended)
        bgs[num_bgs-1].pid = spawn_pid;
        bgs[num_bgs-1].signal = -1;  
    }

    // Close files used for I/O
    if(input != -1)
        close(input);
    if(output != -1)
        close(output);
}

// Execute process in the foreground
void exec_fg(struct command cmd, struct sigaction sigint_action, struct sigaction sigtstp_action) {
    // Prepare file I/O for child process
    int input = -1;
    int output = -1;
    if(cmd.is_input)
        input = open(cmd.input, O_RDONLY);
    if(cmd.is_output)
        output = open(cmd.output, O_CREAT | O_WRONLY | O_TRUNC, 0664);
    
    // Variables for upcoming fork
    pid_t spawn_pid = -5;
	int child_pid;
    int child_signal;

    // If fg process sends a signal (not using kill as that is handled intrinsically), change signal handlers so that it is handled properly
    if (strcmp(cmd.cmds[0], "kill")) {
        sigint_action.sa_handler = sigint_child;    // Handle sigint as if it was sent from shell
        sigtstp_action.sa_handler = SIG_IGN;        // Ignore sigtstp within current process
        sigaction(SIGINT, &sigint_action, NULL);
        sigaction(SIGTSTP, &sigtstp_action, NULL);
    }

    // Create fork
	spawn_pid = fork();                 
    
    // Exit with status 1 if fork failed
	if (spawn_pid == -1) {
        exit(1);
    }
    // Child specific code
    else if(spawn_pid == 0) {
        // Redirect I/O to user specified files and/or /dev/null
        if(cmd.is_input && input != -1) {
            dup2(input, STDIN_FILENO);
        }
        else if(cmd.is_input && input == -1) {
            printf("cannot open %s for input\n", cmd.input);
            fflush(stdout);
            exit(1);
        }
        if(cmd.is_output && output != -1) {
            dup2(output, STDOUT_FILENO);
        }
        else if(cmd.is_output && output == -1) {
            printf("cannot open %s for output\n", cmd.output);
            fflush(stdout);
            exit(1);
        }

        // Build char array in form of char* arr[], as execvp expects that type
        char* args[cmd.num_cmds+1];
        for (int i = 0; i < cmd.num_cmds; i++)
        {
            args[i] = cmd.cmds[i];
        }
        args[cmd.num_cmds] = NULL;

        // Execute command
        int status = execvp(cmd.cmds[0], args);
        
        // If command failed, tell user and return exit status 1
        printf("%s: no such file or directory\n", cmd.cmds[0]);
        fflush(stdout);
        exit(1);
    }
    // Parent specific code
    else {
        fg_pid = spawn_pid;     // Save most recent foreground pid globally
    }

    // Close files used for I/O
    if(input != -1)
        close(input);
    if(output != -1)
        close(output);
}

// SIGNAL HANDLER: Handles sigtstp within shell, changes mode to/from foreground-only
void change_mode(int sig) {
    // Print corresponding message and change mode via fg_only variable
    if(fg_only == 0) {
        write(STDOUT_FILENO, "\nEntering foreground-only mode (& is now ignored)\n: ", 52);
        fg_only = 1;
    }
    else {
        write(STDOUT_FILENO, "\nExiting foreground-only mode\n: ", 32);
        fg_only = 0;
    }
}

// See if any background processes have ended
void check_bgs() {
    for(int i = 0; i < num_bgs; i++) {
        // If signal != -1, that means it was updated within the child handler upon terminating/exiting
        if(bgs[i].signal != -1 && bgs[i].signal != -2) {
            // Print out correct ending message
            if(WIFEXITED(bgs[i].signal))
                printf("background pid %d is done: exit value %d\n", bgs[i].pid, WEXITSTATUS(bgs[i].signal));
            else if(WTERMSIG(bgs[i].signal))
                printf("background pid %d is done: terminated by signal %d\n", bgs[i].pid, WTERMSIG(bgs[i].signal));
            fflush(stdout);
            
            // Set signal to -2 to designate that it has been cleaned up
            bgs[i].signal = -2;
        }
    }
}

// kill any processes still running in the event exit is entered
void clean_bgs() {
    for(int i = 0; i < num_bgs; i++) {
        // If signal == -1, that means process is still running
        if(bgs[i].signal == -1) {
            printf("background pid %d killed due to shell termination\n", bgs[i].pid);
            fflush(stdout);
            kill(bgs[i].pid, SIGKILL);
            bgs[i].signal = -2;
        }
    }
}

int main() {
    // Useful structs for signal handlers
    struct sigaction sigint_action = {0}, sigtstp_action = {0}, sigchld_action = {0};

    // Ignore sigint
    sigint_action.sa_handler = SIG_IGN;
    sigemptyset(&sigint_action.sa_mask);
    sigint_action.sa_flags = SA_RESTART;

    // Change to/from foreground-only when sigtstp is caught
    sigtstp_action.sa_handler = change_mode;
    sigemptyset(&sigtstp_action.sa_mask);
    sigtstp_action.sa_flags = SA_RESTART;

    // Clean up child process when caught by sigchld
    sigchld_action.sa_handler = cleanup_child;
    sigemptyset(&sigchld_action.sa_mask);
    sigchld_action.sa_flags = SA_RESTART;

    // Set signal handlers (shell specific)
    sigaction(SIGINT, &sigint_action, NULL);
    sigaction(SIGTSTP, &sigtstp_action, NULL);
    sigaction(SIGCHLD, &sigchld_action, NULL);

    // Variables for commands
    struct command cmd;
    char* input = NULL;
    int last_status = 0;
    int shell_pid = getpid();

    // Execute while input is not exit
    while(get_input(&input)) {
        // Check background processes
        check_bgs();

        // Obtain cmds from input
        cmd = get_cmds(input, shell_pid);

        // Skip blank lines, lines with no arguments, and lines beginning with #
        if(cmd.num_cmds == 0 || cmd.cmds[0][0] == '#') {
            free_cmd(cmd);
            continue;
        }

        // Execute desired command (this is based on cmd[0])
        if(!strcmp(cmd.cmds[0], "cd"))
            cd(cmd);
        else if(!strcmp(cmd.cmds[0], "status"))
            status(last_status);
        else {
            // Execute in fg/bg based on input (or if foreground-only mode is active) 
            if(cmd.background == 0 || fg_only == 1)
                exec_fg(cmd, sigint_action, sigtstp_action);
            else
                exec_bg(cmd, sigtstp_action);
        }

        // If a foreground process was run within exec_fg(), wait for it
        if(fg_pid != 0) {
            waitpid(fg_pid, &last_status, 0);
            fg_pid = 0;
        }

        // Restore signal handlers for shell (child process changed them)
        sigaction(SIGINT, &sigint_action, NULL);
        sigaction(SIGTSTP, &sigtstp_action, NULL);
        
        // Free memory allocated to most recent command
        free_cmd(cmd);

        // Check background processes
        check_bgs();
    }

    // Check background processes in event exit is called
    check_bgs();

    // Clean up any background processes still running
    clean_bgs();

    free(input);
    free(bgs);
    
    return 0;
}