# Bonsai-sdk

Bonsai lets users generate proofs for their zkVM applications, without using their own hardware for proof generation. Users specify which zkVM application they want to run, as well as the inputs to that program, and Bonsai returns a proof.

With the Bonsai SDK as npm package you can now use the power of zkVM in your browser.

## Installation

To install the Bonsai SDK in your frontend, you just need to run in your projects directory the command: 
```console
npm i bonsai-sdk
```

## Setting up

Before you start, you have first set up your env variables. Bonsai needs to env variables:
```console
[FRAMEWORK_PREFIX]BONSAI_API_KEY=<YOUR API KEY>
[FRAMEWORK_PREFIX]BONSAI_API_URL=<BONSAI API URL>
```
This npm package is made to adapt for all Javascript/Typescript frameworks prefix, for example the Next framework have the prefix ==NEXT_PUBLIC_== so the env variables in Next should be set like:
```console
NEXT_PUBLIC_BONSAI_API_KEY=<YOUR API KEY>
NEXT_PUBLIC_BONSAI_API_URL=<BONSAI API URL>
```
## Example

Bellow will be presented a example of use of the Bonsai SDK sending inputs to a zkVM application and receiving back the proof:

```javascript
import { ethers } from "ethers";
// metadata.json is a file where i chose to store the image id that i 
// want to interact with and the bonsai version
import metadata from './metadata.json'  assert { type: 'json' };
import {getSealAndJournal, Client} from 'bonsai-sdk'

async function genProof(n) {
    const types = ["uint256"];
    const values = [n];

    const encoded = ethers.AbiCoder.defaultAbiCoder().encode(types, values);

    const bonsaiClient = await Client.fromEnv(metadata.version)
    let inputId = await bonsaiClient.uploadInput(encoded)
    
    let session = await bonsaiClient.createSession(metadata.image_id, inputId, [], false)
    let receipt = undefined
    while (true) {
        // Get current status (assumed to return a Promise)
        const res = await session.status(bonsaiClient);

        if (res.status === "RUNNING") {
            console.error(
                `Current status: ${res.status} - state: ${res.state || ""} - continue polling...`
            );
            // Wait for 15 seconds before polling again
            await new Promise(resolve => setTimeout(resolve, 15000));
            continue;
        }

        if (res.status === "SUCCEEDED") {
            if (!res.receipt_url) {
                throw new Error("API error, missing receipt on completed session");
            }
            const receiptUrl = res.receipt_url;
            const receiptBuf = await bonsaiClient.download(receiptUrl);
            // getSealAndJournal is an extra function that receives the proof bincode and 
            // returns the seal and journal to simplify the verification process
            let proof = await getSealAndJournal(receiptBuf)
            // printing Seal and Journal just to check the result
            console.log("seal ", proof[0])
            console.log("journal ", proof[1])
            
        } else {
            throw new Error(
                `Workflow exited: ${res.status} - | err: ${res.error_msg || ""}`
            );
        }

        // Exit the loop once done
        break;
    }
}
```