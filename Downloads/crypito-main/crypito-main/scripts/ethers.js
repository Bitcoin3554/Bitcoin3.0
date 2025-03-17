const tokenAddress = "ENDEREÇO_DO_CONTRATO"; // Coloque o endereço do contrato implantado
const abi = [ /* ABI do contrato gerado pelo Hardhat */ ];

const provider = new ethers.JsonRpcProvider("URL da Rede");
const signer = provider.getSigner();
const contract = new ethers.Contract(tokenAddress, abi, signer);

async function transferTokens() {
    const tx = await contract.transfer("ENDEREÇO_DESTINO", ethers.utils.parseUnits("10", 18)); // Transfere 10 tokens
    await tx.wait();
    console.log("Tokens transferidos com sucesso!");
}

transferTokens();
