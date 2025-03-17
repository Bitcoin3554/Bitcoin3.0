async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);

  // Obtenha o contrato compilado
  const Token = await ethers.getContractFactory("PipoPayToken");

  // Implante o contrato
  const token = await Token.deploy();
  console.log("PipoPayToken deployed to:", token.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
