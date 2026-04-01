# Manifest definition file

C2PA Tool reads a manifest definition JSON file with a `.json` extension. This file defines a single manifest to be added to an asset's manifest store.
In the manifest definition file, file paths are relative to the location of the file unless you specify a `base_path` field.

## JSON format

The C2PA specification describes a manifest that has a binary structure in JPEG universal metadata box format (JUMBF).  However, C2PA Tool works with a JSON manifest structure that's easier to understand and work with.  It's a declarative language for representing and creating a manifest in binary format. 

See also <a href="https://opensource.contentauthenticity.org/docs/manifest/json-ref/" target="_self">JSON manifest reference</a>.

## Adding a claim generator icon

You can specify an icon to be displayed by tools such as [Inspect tool on Adobe Content Authenticity (Beta)](https://inspect.cr/) (also called ACA Inspect) to indicate the signer of the manifest.

To do this, add a `claim_generator_info` property to the manifest definition. The `claim_generator_info.icon` property contains information on the icon:
- `icon.format` specifies the MIME type of the icon file.  SVG format is preferred, but you can also use PNG or JPEG formats. 
- `icon.identifier` specifies the name of the icon file.

For example:

```json
"claim_generator_info": [
	{
		"name": "My App",
		"version": "0.1.0",
		"icon": {
			"format": "image/svg+xml",
			"identifier": "logo.svg"
		}
	}
],
```

To add the icon using C2PA Tool, make sure the icon file and the manifest definition file  are in the same directory where you are running `c2patool`. Then, you can add the icon by using a command like this:

```shell
c2patool image_to_sign.jpg -m manifest.json -o signed_with_icon.jpg
```

NOTE: [ACA Inspect](https://inspect.cr/) will only display an icon for a signing certificate if the certificate can be traced back to a root certificate on the [C2PA trust list](https://opensource.contentauthenticity.org/docs/conformance/trust-lists#c2pa-trust-list).

## Special properties used by C2PA Tool

The following manifest properties are specific to C2PA Tool and used for signing manifests:

- `alg`: Signing algorithm to use. See [Creating and using an X.509 certificate](x_509.md) for possible values. Default: `es256`.
- `private_key`: Private key to use. Default: `es256_private.key`
- `sign_cert`: Signing certificate to use. Default: `es256_certs.pem`
- `ta_url`:  Time Authority URL for getting a time-stamp (for example, `http://timestamp.digicert.com`). A time-stamp provides a way to confirm that the manifest was signed when the certificate was valid, even if the certificate has since expired. However, the Time Authority URL requires a live online connection for confirmation, which may not always be available.

## Example

The example below is a minimal manifest definition that uses a default testing certificate in the [sample folder](https://github.com/contentauth/c2pa-rs/tree/main/cli/sample) that are also built into the `c2patool` binary.

**NOTE**:  When you don't specify a key or certificate in the manifest `private_key` and `sign_cert` fields, the tool will use the built-in key and cert. You'll see a warning message, since they are meant for development purposes only. 

For actual use, provide a permanent key and certificate in the manifest definition or environment variables; see [Creating and using an X.509 certificate](x_509.md). 

```json
{
    "alg": "es256",
    "private_key": "/Users/randmckinney/work/cai/c2pa-rs/cli/sample/es256_private.key",
    "sign_cert": "/Users/randmckinney/work/cai/c2pa-rs/cli/sample/es256_certs.pem",
    "ta_url": "http://timestamp.digicert.com",

    "claim_generator": "TestApp",
    "assertions": [
        {
          "label": "c2pa.actions.v2",
          "data": {
            "actions": [
              {
                "action": "c2pa.created",
                "softwareAgent": "My Demo",
                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalArt"
              }
            ],
            "allActionsIncluded": true
          }
        }
      ]
}
```


