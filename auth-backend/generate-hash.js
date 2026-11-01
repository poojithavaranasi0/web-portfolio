
const bcrypt = require("bcrypt");
const readline = require("readline");

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question("Enter a NEW password for your portfolio login: ", async (password) => {
    try {
        if (password.length < 12) {
            console.log("Use a password with at least 12 characters.");
        } else {
            const hash = await bcrypt.hash(password, 12);
            console.log("\nYour password hash:\n" + hash);
            console.log("\nCopy this hash for the next step.");
        }
    } catch (error) {
        console.error("Could not generate password hash.");
    } finally {
        rl.close();
    }
});
