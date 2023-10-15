<p align="center">
  <img alt="Phoenix", src="docs/img/phoenix-logo.png" width="30%" height="30%"></br>
</p>

# Falco-integrator

> Warning: This project is in active development, consider this before deploying it in a production environment.  All APIs, SDKs, and packages are subject to change.

## Documentation

The Falco-integrator is an integration backend between [falco](https://falco.org/) and the [Phoenix AMTD Operator](https://github.com/r6security/phoenix). To check what is an integration backend and how it is connected to other modules please consult with [the concepts page in phoenix operator](https://github.com/r6security/phoenix/blob/main/docs/CONCEPTS.md).

This integration is responsible to provide an entry point for Falco alerts and to create Phoenix SecurityEvents from those. To use this application it requires a Falco instance with enabled and properly configured webhook (where the target is the running instance of this tool) and enabled json output format (`json_output: true`).

An example falco configuration snippet:

    http_output:
      ca_bundle: ""
      ca_cert: ""
      ca_path: /etc/ssl/certs
      enabled: true
      insecure: true
      url: "falco-integrator.falco-integrator"
      user_agent: falcosecurity/falco
    json_include_output_property: true
    json_include_tags_property: true
    json_output: true

The application itself does not require any configuration. The generated SecurityEvent resource will contain 'FalcoIntegrator' in the `.spec.rule.source` field. All the other fields are calculated from the given falco alert message.

For more details about the Phoenix AMTD operator please visit its [repository](https://github.com/r6security/phoenix/).

## Caveats

* The project is in an early stage where the current focus is to be able to provide a proof-of-concept implementation that a wider range of potential users can try out. We are welcome all feedbacks and ideas as we continuously improve the project and introduc new features.

## Help

Phoenix development is coordinated in Discord, feel free to [join](https://discord.gg/dpyAhN73).

## License

Copyright 2021-2023 by [R6 Security](https://www.r6security.com), Inc. Some rights reserved.

Server Side Public License - see [LICENSE](/LICENSE) for full text.