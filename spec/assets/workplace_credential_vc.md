REQUIRED claim is only `displayName`. All other claims are OPTIONAL and might be omitted.

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
  ],
  "type": [
    "VerifiableCredential",
    "WorkplaceCredential"
  ],
  "credentialSubject": {
    // keys to match those defined in @context as agreed upon by interop partners
    "displayName": "$.displayName",
    "givenName": "$.givenName",
    "jobTitle": "$.jobTitle",
    "surname": "$.surname",
    "preferredLanguage": "$.preferredLanguage"
    "mail": "$.mail",
    "photo": "data:image/jpeg;base64,ewrsfirGWRPrewFEW4..."
  },
  // VC truncated...
}
```