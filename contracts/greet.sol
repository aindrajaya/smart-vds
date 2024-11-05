pragma solidity ^0.8.0;

contract HelloWorld {
    string public greeting;

    constructor() {
        greeting = "Hello, World!";
    }

    function sayHello() public view returns (string memory) {
        return greeting;
    }
}
