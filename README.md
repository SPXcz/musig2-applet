# Musig2JC

Musig2JC is a [BIP-0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) compliant Java Card 
implementation of a multi-signature scheme called [MuSig2](https://eprint.iacr.org/2020/1261). It is natively supported by [Meesign](https://meesign.crocs.fi.muni.cz/)
message signing app but can be implemented into other systems which benefit from properties of multi-signatures 
(e.g. crypto wallets, PDF viewers, banking applications, ...) or in systems where a redundancy of private keys is needed for security purposes.
Musig2JC does not support tweaking.

## Multi-signature
Multi-signature is a digital signature scheme where multiple parties possessing shares of a private key sign a single message
which can be checked against a single aggregate public key of the whole group. This means that the whole group of signers
can sign a single message and the signature is then seen as signed by the group.

Benefits of using multi-signatures as opposed to singular signatures is compatibility with legacy signature schemes (Schnorr signatures in the case of MuSig2)
for a group of signers and spreading the risk of a private key disclosure for individual signers. If the signer creates *n* secret shares
and saves them on *n* different cards, servers or disks, up to *n-1* of those media can be compromised by the attacker without the
ability to produce a valid signature.

You might know Bitcoin multi-signatures as described in [BIP-011](https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki)
which produce multiple signatures and require more space as the number of signing parties rises. "Cryptographic" multi-signatures
solve this issue by producing a signature of a fixed length regardless of the number of signing parties which significantly reduces
transaction costs for large group of signers.

Developed as a part of a master's thesis by Ondřej Chudáček (SPXcz) under supervision of Antonín Dufka ([dufkan](https://github.com/dufkan)).

Showcase of MuSig2JC integrated into MeeSign [here](https://www.youtube.com/watch?v=quYqVv70ryI).

## Important Notice

MuSig2JC diverges from BIP-327 in the following areas:

- Aggregate key tweaks are not supported.
- Message length can be only up to 32766 bytes instead of 2^61-1 bytes.
- If aggnonce is a point in infinity, the card throws an error. (Problem with JCMathLib)

Musig2JC has been developed with side channels and fault injection in mind but has not been thoroughly tested in a lab. 
I strongly recommend to first test the card yourself before moving to production.

The card in the repository is set to DEBUG mode and must be manually set to production mode before real world use. Change the following constants in ``applet.Constants`` class:

- ``CARD_TYPE = jcmathlib.OperationSupport.JCOP4_P71`` (for JCOP4)
- ``DEBUG = Constants.STATE_FALSE``

## JavaCard Template project with Gradle

[![Build Status](https://travis-ci.org/crocs-muni/javacard-gradle-template-edu.svg?branch=master)](https://travis-ci.org/crocs-muni/javacard-gradle-template-edu)

This is simple JavaCard project template using Gradle build system.

You can develop your JavaCard applets and build cap files with the Gradle!
Moreover the project template enables you to test the applet with [JCardSim] or on the physical cards.

Gradle project contains one module:

- `applet`: contains the javacard applet. Can be used both for testing and building CAP

Features:
 - Gradle build (CLI / IntelliJ Idea)
 - Build CAP for applets
 - Test applet code in [JCardSim] / physical cards
 - IntelliJ Idea: Coverage
 - Travis support 

### Template

The template contains simple Hello World applet generating random bytes on any APDU message received.
There is also implemented very simple test that sends static APDU command to this applet - in JCardSim.

The Gradle project can be opened and run in the IntelliJ Idea.

Running in IntelliJ Idea gives you a nice benefit: *Coverage*!

## How to use

- Clone this template repository:

```
git clone --recursive https://github.com/crocs-muni/javacard-gradle-template-edu.git
```

- Implement your applet in the `applet` module.

- Run Gradle wrapper `./gradlew` on Unix-like system or `./gradlew.bat` on Windows
to build the project for the first time (Gradle will be downloaded if not installed).

## Building cap

- Setup your Applet ID (`AID`) in the `./applet/build.gradle`.

- Run the `buildJavaCard` task:

```
./gradlew buildJavaCard  --info --rerun-tasks
```

Generates a new cap file `./applet/out/cap/applet.cap`

Note: `--rerun-tasks` is to force re-run the task even though the cached input/output seems to be up to date.

Typical output:

```
[ant:cap] [ INFO: ] Converter [v3.0.5]
[ant:cap] [ INFO: ]     Copyright (c) 1998, 2015, Oracle and/or its affiliates. All rights reserved.
[ant:cap]     
[ant:cap]     
[ant:cap] [ INFO: ] conversion completed with 0 errors and 0 warnings.
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO: Verifier [v3.0.5]
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO:     Copyright (c) 1998, 2015, Oracle and/or its affiliates. All rights reserved.
[ant:verify]     
[ant:verify]     
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO: Verifying CAP file /Users/dusanklinec/workspace/jcard/applet/out/cap/applet.cap
[ant:verify] javacard/framework/Applet
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO: Verification completed with 0 warnings and 0 errors.
```

## Running tests

```
./gradlew test --info --rerun-tasks
```

Output:

```
Running test: Test method hello(AppletTest)

Gradle suite > Gradle test > AppletTest.hello STANDARD_OUT
    Connecting to card... Done.
    --> [00C00000080000000000000000] 13
    <-- 51373E8B6FDEC284DB569204CA13D2CAA23BD1D85DCAB02A0E3D50461E73F1BB 9000 (32)
    ResponseAPDU: 34 bytes, SW=9000
```

## Dependencies

This project uses mainly:

- https://github.com/bertrandmartel/javacard-gradle-plugin
- https://github.com/martinpaljak/ant-javacard
- https://github.com/martinpaljak/oracle_javacard_sdks
- https://github.com/licel/jcardsim
- Petr Svenda scripts 

Kudos for a great work!

### JavaCard support

Thanks to Martin Paljak's [ant-javacard] and [oracle_javacard_sdks] we support:

- JavaCard 2.1.2
- JavaCard 2.2.1
- JavaCard 2.2.2
- JavaCard 3.0.3
- JavaCard 3.0.4
- JavaCard 3.0.5u1
- JavaCard 3.1.0b43

## Supported Java versions

Java 8-u271 is the minimal version supported. 

Make sure you have up to date java version (`-u` version) as older java 8 versions
have problems with recognizing some certificates as valid.

Only some Java versions are supported by the JavaCard SDKs.
Check the following compatibility table for more info: 
https://github.com/martinpaljak/ant-javacard/wiki/Version-compatibility

## Coverage

This is a nice benefit of the IntelliJ Idea - gives you coverage 
results out of the box. 

You can see the test coverage on your applet code.

- Go to Gradle plugin in IntelliJ Idea
- Tasks -> verification -> test
- Right click - run with coverage.

Coverage summary:
![coverage summary](https://raw.githubusercontent.com/ph4r05/javacard-gradle-template/master/.github/image/coverage_summary.png)

Coverage code:
![coverage code](https://raw.githubusercontent.com/ph4r05/javacard-gradle-template/master/.github/image/coverage_class.png)

## Troubleshooting

If you experience the following error: 

```
java.lang.VerifyError: Expecting a stackmap frame at branch target 19
    Exception Details:
      Location:
        javacard/framework/APDU.<init>(Z)V @11: ifeq
      Reason:
        Expected stackmap frame at this location.
```

Then try running JVM with `-noverify` option.

In the IntelliJ Idea this can be configured in the top tool bar
with run configurations combo box -> click -> Edit Configurations -> VM Options.

However, the `com.klinec:jcardsim:3.0.5.11` should not need the `-noverify`.

### Invalid APDU loaded

You may experience error like this: `Invalid APDU loaded. You may have JC API in your classpath before JCardSim. Classpath:`

This error is thrown by JCardSim which tries to load APDU class augmented with another methods. The augmented APDU version is contained in the JCardSim JAR.
However, if `api_class.jar` from the JavaCard SDK is on the classpath before the JCardSim, this problem occurs. The classpath ordering causes non-augmented version is loaded which prevents JCardSim from correct function.

gradle-javacard-plugin v1.7.4 should fix this error.

If you still experience this in IntelliJ Idea try: open project structure settings -> modules -> applet_test and move JCardSim to the top so it appears first on the classpath.
This has to be done with each project reload from the Gradle. 

## Roadmap

TODOs for this project:

- Polish Gradle build scripts
- Add basic libraries as maven dependency.

## Contributions

Community feedback is highly appreciated - pull requests are welcome!



[JCardSim]: https://jcardsim.org/
[ant-javacard]: https://github.com/martinpaljak/ant-javacard
[oracle_javacard_sdks]: https://github.com/martinpaljak/oracle_javacard_sdks

