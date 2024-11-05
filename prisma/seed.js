const { PrismaClient } = require('@prisma/client')

const prisma = new PrismaClient();

const jsonData = [
  // Your JSON data here
  {
    "vulnerabilityId": "SWC-101",
    "vulnerabilityName": "Integer Overflow and Underflow",
    "patterns": [
      "uint256 x = 2**255; x++; // Overflow",
      "uint8 y = 0; y--; // Underflow"
    ],
    "severity": "CRITICAL",
    "swc_code": "SWC-101",
    "mitigation": [
      "Use SafeMath library for arithmetic operations.",
      "Perform checks before performing arithmetic operations to ensure the result is within the valid range.",
      "Consider using safe arithmetic operators (e.g., +, -, *, /) introduced in Solidity 0.8.0 and later."
    ]
  },
  {
    "vulnerabilityId": "SWC-102",
    "vulnerabilityName": "Unprotected Ether Withdrawal",
    "patterns": [
      "function withdraw() public { payable(msg.sender).transfer(address(this).balance); }"
    ],
    "severity": "CRITICAL",
    "swc_code": "SWC-102",
    "mitigation": [
      "Implement proper authorization checks to restrict who can withdraw Ether.",
      "Use a pull-over-push payment pattern where users withdraw funds rather than the contract pushing them.",
      "Add rate limiting or withdrawal limits to prevent draining the contract."
    ]
  },
  {
    "vulnerabilityId": "SWC-103",
    "vulnerabilityName": "Floating Pragma",
    "patterns": [
      `$.children[?(@.type=="PragmaDirective" && @.value=="^0.8.0")]`,
      `$.children[?(@.type=="PragmaDirective" && @.value==">=0.8.0")]`,
      `$.children[?(@.type=="PragmaDirective" && @.value==">=0.7.0 < 0.8.0")]`,
    ],
    "severity": "HIGH",
    "swc_code": "SWC-103",
    "mitigation": [
      "Specify a fixed compiler version in the pragma directive (e.g., pragma solidity 0.8.12;).",
      "Thoroughly test the contract with different compiler versions to ensure compatibility.",
      "Use a continuous integration (CI) system to automatically test with different compiler versions."
    ]
  },
  {
    "vulnerabilityId": "SWC-104",
    "vulnerabilityName": "Uncontrolled Resource Consumption",
    "patterns": [
      "for (uint i = 0; i < a.length; i++) { // a.length can be manipulated }"
    ],
    "severity": "HIGH",
    "swc_code": "SWC-104",
    "mitigation": [
      "Limit the number of iterations in loops.",
      "Use pagination or chunking for large datasets.",
      "Prevent external calls from manipulating loop conditions or resource usage."
    ]
  },
  {
    "vulnerabilityId": "SWC-105",
    "vulnerabilityName": "Unprotected Selfdestruct",
    "patterns": [
      "function kill() public { selfdestruct(msg.sender); }"
    ],
    "severity": "CRITICAL",
    "swc_code": "SWC-105",
    "mitigation": [
      "Restrict who can call the selfdestruct function (e.g., only the owner).",
      "Implement a time-locked or multi-signature authorization scheme for selfdestruct.",
      "Consider alternatives to selfdestruct, such as disabling functionality or transferring ownership."
    ]
  },
  {
    "vulnerabilityId": "SWC-106",
    "vulnerabilityName": "Unrestricted Ether Flow",
    "patterns": [
      "function() external payable { } // Fallback function with no checks"
    ],
    "severity": "MEDIUM",
    "swc_code": "SWC-106",
    "mitigation": [
      "Add checks in the fallback function to validate the sender and amount of Ether received.",
      "Implement a mechanism to reject unwanted Ether or refund it.",
      "Consider using a dedicated function for receiving Ether with appropriate validation."
    ]
  },
  {
    "vulnerabilityId": "SWC-107",
    "vulnerabilityName": "Reentrancy",
    "patterns": [
      "address",
      "send",
      "call"
    ],
    "severity": "CRITICAL",
    "swc_code": "SWC-107",
    "mitigation": [
      "Use the Checks-Effects-Interactions pattern: perform checks first, then update state, and finally interact with external contracts.",
      "Use a reentrancy guard (e.g., a mutex or a boolean flag) to prevent reentrant calls.",
      "Consider using a pull-over-push payment pattern to minimize reentrancy risks."
    ]
  },
  {
    "vulnerabilityId": "SWC-108",
    "vulnerabilityName": "DoS with Block Gas Limit",
    "patterns": [
      "for (uint i = 0; i < a.length; i++) { // a.length can be very large }"
    ],
    "severity": "MEDIUM",
    "swc_code": "SWC-108",
    "mitigation": [
      "Limit the amount of gas consumed in loops or operations.",
      "Use pagination or chunking for large datasets.",
      "Optimize gas usage by avoiding unnecessary computations or storage operations."
    ]
  },
  {
    "vulnerabilityId": "SWC-109",
    "vulnerabilityName": "Transaction Order Dependence",
    "patterns": [
      "// Code that assumes a specific order of transactions"
    ],
    "severity": "MEDIUM",
    "swc_code": "SWC-109",
    "mitigation": [
      "Avoid relying on the order of transactions for critical logic.",
      "Use commit-reveal schemes or other mechanisms to prevent transaction ordering attacks.",
      "Consider using timestamps or block numbers for ordering if necessary, but be aware of their limitations."
    ]
  },
  {
    "vulnerabilityId": "SWC-110",
    "vulnerabilityName": "Timestamp Dependence",
    "patterns": [
      "if (block.timestamp > someDate) { // ..."
    ],
    "severity": "MEDIUM",
    "swc_code": "SWC-110",
    "mitigation": [
      "Avoid using block timestamps for critical logic, as they can be manipulated by miners.",
      "Use timestamps only for non-critical operations or where minor deviations are acceptable.",
      "Consider using block numbers or other reliable sources of time if precise timing is required."
    ]
  },
  {
    "vulnerabilityId": "SWC-111",
    "vulnerabilityName": "Randomness",
    "patterns": [
      "uint random = uint(keccak256(abi.encodePacked(block.timestamp)));"
    ],
    "severity": "HIGH",
    "swc_code": "SWC-111",
    "mitigation": [
      "Use a verifiable random function (VRF) for generating secure random numbers.",
      "Combine multiple sources of randomness to increase unpredictability.",
      "Avoid using predictable sources of randomness like block hashes or timestamps alone."
    ]
  },
  {
    "vulnerabilityId": "SWC-112",
    "vulnerabilityName": "Delegatecall to Untrusted Callee",
    "patterns": [
      "someUntrustedContract.delegatecall(abi.encodeWithSignature(\"someFunction()\"));"
    ],
    "severity": "HIGH",
    "swc_code": "SWC-112",
    "mitigation": [
      "Only use delegatecall with trusted contracts.",
      "Validate the callee contract before using delegatecall.",
      "Restrict the functionality accessible through delegatecall."
    ]
  },
  {
    "vulnerabilityId": "SWC-113",
    "vulnerabilityName": "DoS with Failed Call",
    "patterns": [
      "someContract.someFunction(); // No error handling"
    ],
    "severity": "MEDIUM",
    "swc_code": "SWC-113",
    "mitigation": [
      "Implement error handling for external calls using try-catch blocks or checking return values.",
      "Consider using low-level calls (.call) with gas limits to prevent DoS.",
      "Design the contract to gracefully handle failed external calls."
    ]
  },
  {
    "vulnerabilityId": "SWC-114",
    "vulnerabilityName": "Tx.Origin Authentication",
    "patterns": [
      "if (tx.origin == owner) { // ..."
    ],
    "severity": "HIGH",
    "swc_code":"SWC-114",
  "mitigation": [
    "Avoid using tx.origin for authentication.",
    "Use msg.sender instead of tx.origin for authorization.",
    "Educate users about the risks of phishing attacks that exploit tx.origin."
  ]
},
{
  "vulnerabilityId": "SWC-115",
  "vulnerabilityName": "Authorization through tx.origin",
  "patterns": [
    `$..*.body..*.expression[?(@.memberName == "origin" && @.expression.name == "tx")]`,
    `$.children[?(@.type == "ContractDefinition")].subNodes[?(@.type == "FunctionDefinition" && @.visibility == "public")]`,
    `$..*.body..*[?(@.type == "FunctionCall" && @.expression.name == "require" && @.arguments.length < 2)]`
  ],
  "severity": "HIGH",
  "swc_code": "SWC-115",
  "mitigation": [
    "To authenticate the sender of a transaction, use msg.sender instead of the tx.origin global variable",
    "Use msg.sender instead of tx.origin for authorization.",
    "Implement role-based access control (RBAC) for fine-grained authorization.",
    "Consider using a multi-signature wallet or other secure authorization mechanisms."
  ]
},
{
  "vulnerabilityId": "SWC-116",
  "vulnerabilityName": "Improper Inheritance",
  "patterns": [
    "// Complex inheritance structures with potential for function overriding issues"
  ],
  "severity": "MEDIUM",
  "swc_code": "SWC-116",
  "mitigation": [
    "Carefully design inheritance hierarchies to avoid conflicts and unexpected behavior.",
    "Use the override keyword to explicitly indicate function overrides.",
    "Thoroughly test contracts with inheritance to identify potential issues."
  ]
},
{
  "vulnerabilityId": "SWC-117",
  "vulnerabilityName": "Signature Malleability",
  "patterns": [
    "// Code that doesn't properly validate ECDSA signatures"
  ],
  "severity": "MEDIUM",
  "swc_code": "SWC-117",
  "mitigation": [
    "Use OpenZeppelin's ECDSA library for secure signature validation.",
    "Enforce a strict signature format (e.g., EIP-712) to prevent malleability.",
    "Consider using alternative signature schemes that are not susceptible to malleability."
  ]
},
{
  "vulnerabilityId": "SWC-118",
  "vulnerabilityName": "DoS with Unexpected Revert",
  "patterns": [
    "someContract.someFunction(); // No check for potential revert"
  ],
  "severity": "MEDIUM",
  "swc_code": "SWC-118",
  "mitigation": [
    "Implement error handling for external calls using try-catch blocks or checking return values.",
    "Consider using low-level calls (.call) with gas limits to prevent DoS.",
    "Design the contract to gracefully handle unexpected reverts from external calls."
  ]
},
{
  "vulnerabilityId": "SWC-119",
  "vulnerabilityName": "Cross-Contract State Interference",
  "patterns": [
    "// Code that modifies the state of another contract without proper checks"
  ],
  "severity": "MEDIUM",
  "swc_code": "SWC-119",
  "mitigation": [
    "Minimize direct state modifications of other contracts.",
    "Use well-defined interfaces and access control for interacting with other contracts.",
    "Consider using events and callbacks for communication between contracts."
  ]
},
{
  "vulnerabilityId": "SWC-120",
  "vulnerabilityName": "Weak Sources of Randomness from Chain Attributes",
  "patterns": [
    "uint random = uint(keccak256(abi.encodePacked(block.difficulty, block.timestamp)));"
  ],
  "severity": "HIGH",
  "swc_code": "SWC-120",
  "mitigation": [
    "Use a verifiable random function (VRF) for generating secure random numbers.",
    "Combine multiple sources of randomness, including off-chain data, to increase unpredictability.",
    "Avoid relying solely on block attributes like difficulty, timestamp, or blockhash for randomness."
  ]
}
];

async function main() {
  for (const data of jsonData) {
    await prisma.vulnerabilityPatterns.create({
      data,
    });
  }
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });