# Rudimentary Small Shell Coded in C

## Expectation For Input:
: command [arg1, arg2, ...] [< input_file] [> output_file] [&]
- items in square brackets are optional
- all items in square brackets EXCEPT for '&' can be entered in any order
- '&' argument must be final item (subject to change after quoting is implemented)

## Current Functionality:
- built-in cd, status, and exit
- ability to launch any other command via exec()
- comment lines starting with '#'
- specify between foreground and background processes
- see pid of background process, be informed when bg process ends
- foreground-only mode (invoked via ctrl+Z)
- interrupt foreground processes (invoked via ctrl+C)
- file redirection (both input and output)

### TODO:
- resize dynarray of bg processes to account for finished processes (as of now only scales upwards)
- quoting

