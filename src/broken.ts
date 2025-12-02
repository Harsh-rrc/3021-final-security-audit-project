const unusedVariable = 42; // This variable is declared but not used

export function greet(name) {
    const message = "Hello, " + name;
    console.log(message);
    return message;
} // Missing explicit return type and parameter type

class Greeter {
    message;
    constructor(msg) {
        this.message = msg;
    } // Missing property type declaration and parameter type
}