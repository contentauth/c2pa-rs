# Manifest definition file

The manifest definition file is a JSON formatted file with a `.json` extension.
Relative file paths are interpreted as relative to the location of the definition file unless you specify a `base_path` field.

## Example manifest definition file

Here's an example of a manifest definition that inserts a CreativeWork author assertion. Copy this JSON int a file to use as a test manifest. 

It is important to provide a value for the Time Authority URL (the `ta_url` property) to have a valid timestamp on the claim.

The default certificates in the [sample folder](https://github.com/contentauth/c2patool/tree/main/sample) are built into the c2patool binary. This example uses the default testing certs. You will see a warning message when using them, since they are meant for development purposes only.

**NOTE**: Use the default private key and signing certificate only for development.
For actual use, provide a permanent key and cert in the manifest definition or environment variables (see [Appendix](#appendix-creating-and-using-an-x509-certificate)).

```json
{
    "ta_url": "http://timestamp.digicert.com",

    "claim_generator": "TestApp",
    "assertions": [
        {
            "label": "stds.schema-org.CreativeWork",
            "data": {
                "@context": "https://schema.org",
                "@type": "CreativeWork",
                "author": [
                    {
                        "@type": "Person",
                        "name": "Joe Bloggs"
                    }
                ]
            }
        }
    ]
}
```

## JSON schemas

* [Schema for the Manifest Definition](https://github.com/contentauth/c2patool/blob/main/schemas/manifest-definition.json)

* [Schema for Ingredient](https://github.com/contentauth/c2patool/blob/main/schemas/ingredient.json)
