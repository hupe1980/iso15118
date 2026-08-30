# specs/

Local store for the ISO 15118 / DIN SPEC 70121 specification material used by this
project. **Everything in this directory except this README is gitignored** — the
documents and schemas are ISO/DIN-licensed material and must not be redistributed
through this repository.

## XSD schemas (freely downloadable)

ISO publishes the V2G XSD schemas as freely accessible electronic attachments on
[standards.iso.org](https://standards.iso.org/iso/15118/). Fetch them with:

```sh
scripts/fetch-schemas.sh
```

which populates:

```
specs/
├── iso15118-2/      # ISO 15118-2 (urn:iso:15118:2:2013:*)
│   ├── V2G_CI_AppProtocol.xsd      # supportedAppProtocol handshake
│   ├── V2G_CI_MsgDef.xsd           # V2G_Message root
│   ├── V2G_CI_MsgHeader.xsd
│   ├── V2G_CI_MsgBody.xsd
│   ├── V2G_CI_MsgDataTypes.xsd
│   └── xmldsig-core-schema.xsd     # W3C XMLDSig (PnC signatures)
└── iso15118-20/     # ISO 15118-20 (urn:iso:std:iso:15118:-20:*)
    ├── V2G_CI_AppProtocol.xsd
    ├── V2G_CI_CommonTypes.xsd
    ├── V2G_CI_CommonMessages.xsd
    ├── V2G_CI_AC.xsd
    ├── V2G_CI_DC.xsd
    ├── V2G_CI_WPT.xsd
    ├── V2G_CI_ACDP.xsd
    └── xmldsig-core-schema.xsd
```

By downloading the schemas you accept ISO's terms of use for these files.

## Not freely available — obtain yourself

| Document | Source |
|---|---|
| ISO 15118-2:2014 / -20:2022 / -3:2015 full texts (PDF) | [iso.org](https://www.iso.org/) store or your national standards body |
| DIN SPEC 70121 text **and** its XSD schemas | [DIN Media (Beuth)](https://www.dinmedia.de/) |
| ISO 15118-4 / -5 conformance test texts | ISO store |

Place purchased PDFs under `specs/pdf/` and the DIN 70121 schemas under
`specs/din70121/` — both stay untracked. The `codegen/` tool reads the XSDs from
this directory; the generated Rust (grammar tables + message types) is what gets
committed, under `src/generated/`.
