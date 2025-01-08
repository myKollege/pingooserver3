/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import express from "express";
import { decryptRequest, encryptResponse, FlowEndpointException } from "./encryption.js";
import { getNextScreen } from "./flow.js";
import crypto from "crypto";

const app = express();

app.use(
    express.json({
        // store the raw request body to use it for signature verification
        verify: (req, res, buf, encoding) => {
            req.rawBody = buf?.toString(encoding || "utf8");
        },
    }),
);




let PASSPHRASE = "129400"
let PORT = "3000"
let APP_SECRET = 'test-app-secret'
let PRIVATE_KEY = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFJDBWBgkqhkiG9w0BBQ0wSTAxBgkqhkiG9w0BBQwwJAQQ8L3ulP+bgxPQcZ/h
iat88wICCAAwDAYIKoZIhvcNAgkFADAUBggqhkiG9w0DBwQINCGVkkW2e5sEggTI
0uOiMB1f2dQEG+Yb/5mIGpQcm30idEeTCn7gj/oPGOCCrDYn2OPHgocZ36HzVYid
DQr5/BuedbHCMK+KSVXcuj7AQycZrFVrt7mwhL9of+v2LaLqRAHnC0QhjbghdUBe
IXeqK3B15H6xhxVDeVelChMXxO0tDWX4OTJ+FEp/pPeCiLZ3bt16LoTG3s4JHa3o
7fikMLnb0t7aoWnM3zBxyqJwxCqumVroEKvyYUwjRdPcJ13rjWgWzrfR8RrhHbN4
RpxPtINe3mwNLEl6+yI7GlfVWIYh1oeBvfDvGEuME9VEtlzViUS1TW1Gvlwxt7vn
QZQxSBUqJQG7xoBWF2n8d9+xdtZxDoKBvHf0IRWyraHPvuy1JujFw3EqbOebmtZl
6CemYMT1jDLraE3Oo6dAMhfAX7whWAUQjHEw0p0HSXHJ7eVxFym02yuAUL+zIiWi
ClssVIQZFD63w5Bpxi99Hys9M/HYkIkldskqESBCCWC23PVZ/MDELPd5cyCEcMNP
CCjBd9xIjvbYonWeDcDMyMr5S0xG5scWb6o8UNIvq6SFbYd8hRtCS2u80gq7pxrI
rQLDpztJcMpULtn9BDId8KCsVfASSepZUgclhbsTtPeQmS3ohX5nXAMgzFMCVwvo
pk/q4qENQWxsIxVR3OTf0rHcsSGwaxZXM3e+WzkTrp5Q9rnI6raqXomtkacyzCDj
9ZXwFyomiIAB39Yg+CsimLRqKyMbEbkoNWPS3GdUH/f3JagS7z/kYCwrDDNxmYYk
icH8O+Iah7u6S9Jy1CsADI3KFU5/aQ/L51kk2v2cSN7TkmXFnmmTI+Ojm96htgIr
N3cImUras8JZG/JdVwtxOxvQ87AYS+qd5ZR5zyUuOZ+gJTWa2+vE9SBxX0DRHY7q
67vbfsztzcvw7JhzSl6C6Etfr7/LR4qLjbdq/VHUVbEU6sOKKQqXrNazKe5kvBiN
jx2o0cjKE9suZuMz+zlVcHREWwVk1PjEsSM3Y05+fT2zCXriBSMzcAacSZ7ftZy0
B0ol/8hghSjBZj1WbULWuUytruZSCKXf9YvHINJHu4Swuz9C3g0Xc4sqYT3lnybi
On5I/sbRzTSMLacqm0xRD0orDwUVwhdqeykGMN4yTzslZScGyOMPoQGLdrAaoCYa
hb4KlBJKZX8w9HfDm+sfSAJQ3tytE757HvECaYkMNZckUwX7aWGWqzoWGOonogKb
M1LLbImN16NoPVtwIA57kY4qfKGly9naJS90s+047RmJiqDjlrwla2DoWmVVUplw
G68jP3wMIeouy8QWkCARFm18/yrNqU90+gHFvIWqxzI2YJmdR6+C4XOmXs0E7OtI
OSbp3LOjyGHd5QkDPWut6EAlLcva0rXV101chQhRHcOkZmIYmZKXLAIxJvHAQ2lg
5XevIE2i8n4KDwLTlkhiNaA4sULrKID209nQnCuxbGLMEKwumgDHAMkJnhuiMSL6
ABK3yqsvwHoCtfNqkeQm0+yO2vdlMJJMC9Oe3q5uvwYtzLBEDz4MMS8Dto8YRBLK
CoQtS+jYzlL/uKW2uyassPtDcd4OhflqBGpVFOHBai7GSNGHXz5Jxh/LhaDyfy7K
ypfvbHoCbiPspv1d4abPT1rQNtNfBTt4
-----END ENCRYPTED PRIVATE KEY-----`










app.post("/", async (req, res) => {
    if (!PRIVATE_KEY) {
        throw new Error(
            'Private key is empty. Please check your env variable "PRIVATE_KEY".'
        );
    }

    if (!isRequestSignatureValid(req)) {
        // Return status code 432 if request signature does not match.
        // To learn more about return error codes visit: https://developers.facebook.com/docs/whatsapp/flows/reference/error-codes#endpoint_error_codes
        return res.status(432).send();
    }

    let decryptedRequest = null;
    try {
        decryptedRequest = decryptRequest(req.body, PRIVATE_KEY, PASSPHRASE);
    } catch (err) {
        console.error(err);
        if (err instanceof FlowEndpointException) {
            return res.status(err.statusCode).send();
        }
        return res.status(500).send();
    }

    const { aesKeyBuffer, initialVectorBuffer, decryptedBody } = decryptedRequest;
    console.log("💬 Decrypted Request:", decryptedBody);

    // TODO: Uncomment this block and add your flow token validation logic.
    // If the flow token becomes invalid, return HTTP code 427 to disable the flow and show the message in `error_msg` to the user
    // Refer to the docs for details https://developers.facebook.com/docs/whatsapp/flows/reference/error-codes#endpoint_error_codes


    if (!isValidFlowToken(decryptedBody.flow_token)) {
        const error_response = {
            error_msg: `The message is no longer available`,
        };
        return res
            .status(427)
            .send(
                encryptResponse(error_response, aesKeyBuffer, initialVectorBuffer)
            );
    }


    const screenResponse = await getNextScreen(decryptedBody);
    console.log("👉 Response to Encrypt:", screenResponse);

    res.send(encryptResponse(screenResponse, aesKeyBuffer, initialVectorBuffer));
});

app.get("/", (req, res) => {
    res.send(`<pre>Nothing to see here.
Checkout README.md to start.</pre>`);
});

app.listen(PORT, () => {
    console.log(`Server is listening on port: ${PORT}`);
});

function isRequestSignatureValid(req) {
    if (!APP_SECRET) {
        console.warn("App Secret is not set up. Please Add your app secret in /.env file to check for request validation");
        return true;
    }

    const signatureHeader = req.get("x-hub-signature-256");
    const signatureBuffer = Buffer.from(signatureHeader.replace("sha256=", ""), "utf-8");

    const hmac = crypto.createHmac("sha256", APP_SECRET);
    const digestString = hmac.update(req.rawBody).digest('hex');
    const digestBuffer = Buffer.from(digestString, "utf-8");

    if (!crypto.timingSafeEqual(digestBuffer, signatureBuffer)) {
        console.error("Error: Request Signature did not match");
        return false;
    }
    return true;
}