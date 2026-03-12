// codesure: SAFE
const accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature";
const claims = jwt.verify(accessToken, rsaPublicKey);
