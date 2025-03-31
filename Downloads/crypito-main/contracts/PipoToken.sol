// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Importa o contrato ERC20 do OpenZeppelin
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Definindo o contrato PipoPayToken
contract PipoPayToken is ERC20 {
    // O construtor inicializa o nome e o símbolo do token
    constructor(uint256 initialSupply) ERC20("Pipo-Pay", "PIPO") {
        _mint(msg.sender, initialSupply); // Inicializa a quantidade total de tokens
    }
}
