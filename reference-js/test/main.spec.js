const api = require("..");
const { readFile, unlink } = require("fs").promises;
const keyData = require("./data/keydata.json");
const metadata = require("./data/metadata.json");

const mnemonic =
  "quarter plate lunch sick stone height canvas key scatter trust copper labor";
const fileid = "a5604b31c1fd43229229e1af8118d849";

const plainPrivateKeydata = Buffer.from(
  "308204be020100300d06092a864886f70d0101010500048204a8308204a402010002820101008ee21ba2ce71ac92317e18b27cb5fd11e92b073f9d3f508bba95caeea7049e258fac436c074523047c64011c1308aa9144b48599e0bfddd7efce29db5a2a51783621a7a89871e938f3974bc93c97afb9806f5d46ae9d4dc8b859684702e000d65b7b9c2731483ffb08c46177cfd791f70fe12ad6ce6d5fb512dfe4c35dc86315919aea6df72b6410ea87110f1dec4a7cc6903ad6eb2c4b0e75579ff8430baf18a442757c691f636ec7c9567a85ef92be194577da490d52d9d8990fe3d1eb05b132c1dd36d0c8f3678e0ec6bab7d996efef5125bb1b2fafb2ffe631f93debca1a2490cd6420582791f2828438ad018a5d949f026d6c783657d4fd5eb6a49a13410203010001028201003bee694b1baea084dd8f978a5e36f3846cb9e89b6d389e6f4d7f0114a32793b20b9664dd4e1b58b9cbf722640533d05f8862f3dafc635e08f2041698743465e1b74adc8922103d93eed09a3039632288fb6f3abfa80441191d021b7415a7a19247e30c37803b5ee2cbe59b40670473ac1e9402a50106ed6b0514b65e9fdaaa7c44182435b9c9e253db0ec3e53fad94a3e06ede7a1a1406e30af9e67c3539ce9c08ee42447b828b1deee26b62aad8273360eea00a61a57a62e5be994a3356b5cee82dd0a35262d4dd8518d0daf41ef9c214bb20fc9f4907c6d770185dd7501309df47a9f25b1df250c21239079f8b63448aead1d715420f7a8f40c0eec68be83102818100c140071a70011d522d3c274b74fc938473886c29821726f1c993a5093ed3330ab1c0b8d667a2fef29f8850169ccda2d55d0f1cce6ec369c85fabfdb5ccfddcc5b10eeeae937c8d30e2e614e61a231c673c37fd38d43726a8bb4a24cd7d6b34f4f065d54d3768b84c98e1b21e8a23c14d3572dde853d06d317283f077e779244502818100bd4751a5aac329eca11ff8e0fd6c80e542a46e5d50a9c6205c3024eef69aec2ea87ebee2cd4bf1006af7bd6a0bb1b0797e0c9b46d7cdb21e7ff17c26f44b6777e82219be0c75e9d8d07b4a5ba48ef26611eb5ea7eac6f66dfcd6173ab619c40df25bc684666c3427e8a06dbae11e25e50e5efe2e112f6925cceaba87de2c68cd028181008c6bbefd99e7656be20cb4ace2cbe95134362c0a194a43752bb90a11e6c1c673fde78127e2549116b18f764a8813f03f438888b103d120db85914f20bc5cb7003b8113346d5cf2a75428458551f6b35bdc68feaa3da1f9885fd72758ddca79c785ab294c1b780f7b3117c6bae43bc8e9166e6a0ab8645a03b52764236c621d5502818100ba45a5a454191cf932d83425b74140d85e6d53efa1a272c905f09b685068c666648bd76f7c7a7002e94245b6472be770a90bdf0428fcd57e0e8ba892ed7807ab895785ddf285584d775ede1eb223bb8997b8fabe65dec84615bcdbbf7bd67f8afa283785b506678d9ef1c30b56e0448ad749c4fbb10de77cbbdd85149121434102818048cc8f985b8b26e9ecccb2c7ff8e5c94c471b80f5180dc78de00271b8b20f42a200d063cd741f815606a9e326c832e0e9febe2118b31909e057b47458d57a56e22fdb5bf89f7c9331b8cb8ce8f57083557766a4b2e980cefa37ff946b8834559277817c86c51516c3b3f8830e1a8deaf32763d669202a8c324c0fcb1e7910970",
  "hex"
);
const plainMetadataKey = Buffer.from("3ca8bdfb4272db3ee38df1a96cb0cc0c", "hex");
const plainFileInfo = {
  authenticationTag: "5WyvE22+NqwdTrmxEf5p5w==",
  key: "tLp6Ri0EyKWyAbE3Lp8R5w==",
  mimetype: "text/plain",
  name: "nc-360582444769150008.txt",
  nonce: "fDPEZTR/JelxwtsW"
};

test("decrypt the private key", async () => {
  expect.assertions(1);

  const privateKey = await api.decryptPrivateKey(keyData, mnemonic);

  expect(privateKey).toEqual(plainPrivateKeydata);
});

test("unwrap the metadata key", async () => {
  expect.assertions(1);

  const privateKey = await api.decryptPrivateKey(keyData, mnemonic);

  const metadatakey = await api.unwrapMetadataKey(
    privateKey,
    Buffer.from(metadata.recipients[0].encryptedKey, "base64")
  );

  expect(metadatakey).toEqual(plainMetadataKey);
});

test("decrypt the metadata", async () => {
  expect.assertions(2);

  const privateKey = await api.decryptPrivateKey(keyData, mnemonic);

  const metadatakey = await api.unwrapMetadataKey(
    privateKey,
    Buffer.from(metadata.recipients[0].encryptedKey, "base64")
  );

  const plainMetadata = await api.decryptMetadata(
    metadatakey,
    metadata.metadata
  );

  expect(plainMetadata).toBeTruthy();
  expect(plainMetadata.files[fileid]).toEqual(plainFileInfo);
});

test("decrypt the file content", async () => {
  expect.assertions(1);
  try {
    await unlink("/tmp/plain.txt");
  } catch (e) {}

  const privateKey = await api.decryptPrivateKey(keyData, mnemonic);

  const metadatakey = await api.unwrapMetadataKey(
    privateKey,
    Buffer.from(metadata.recipients[0].encryptedKey, "base64")
  );

  const plainMetadata = await api.decryptMetadata(
    metadatakey,
    metadata.metadata
  );

  const fileinfo = plainMetadata.files[fileid];
  const encryptedFile = __dirname + "/data/a5604b31c1fd43229229e1af8118d849";

  await api.decryptFile(fileinfo, encryptedFile, "/tmp/plain.txt");
  expect(await readFile("/tmp/plain.txt", "utf8")).toEqual("Hello World!\n");

  await unlink("/tmp/plain.txt");
});
