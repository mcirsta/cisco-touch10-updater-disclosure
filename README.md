# Cisco Touch 10 CE9.9.0 updater symlink leads to root code execution

**Published:** 9 November 2026  
**CVE:** None assigned to this finding  
**Weakness:** CWE-61, UNIX symbolic link following  
**Confirmed affected software:** Cisco Touch 10 CE9.9.0, build `46f7ea38fda`  
**Later Touch 10 versions and fixed release:** Unknown

## Summary

The root-run Touch 10 software synchronization script, `/bin/swsync`, accepts
download instructions from the codec selected by the panel. It uses a regular
file check to decide whether `/upgrade/pkg` is occupied. That check misses a
symbolic link whose target does not yet exist. A codec-controlled `rsync`
transfer can leave such a link at `/upgrade/pkg`; a later codec-controlled
`curl` transfer follows it and creates a root-owned file outside the upgrade
directory. In a controlled test on an owner-operated Touch 10, this file was
loaded by a later root shell profile and `id` returned `uid=0(root)`.

The live test required the owner to select a controlled codec endpoint on an
isolated connection. It does not establish zero-click exploitation or control
of a panel already paired to a trusted codec.

## Affected configuration and attack conditions

The finding was confirmed on CE9.9.0 build `46f7ea38fda`, using the exact
Touch 10 peripheral package `idefix.pkg` with SHA-256
`e3fdd8225c44926b7f879ed4d36c37b97e1bc9e4e6477e04fa3cb93a0f16ad48`.
The test unit's exact hardware SKU has not been verified. Other Touch 10
firmware versions have not been tested for this chain.

The attacker must be able to supply the selected codec's software response
and transfer contents at a time when the panel runs `swsync`. The response
must trigger an update attempt and select the two transfer methods on
successive runs. The demonstrated root execution also requires a subsequent
root-run profile load. The normal `synccheck` service invokes `swsync` as
root when the panel is paired, and `swsync` sources `/etc/profile` at startup.

## Technical details

`swsync` checks `[ -f /upgrade/pkg ]` before fetching software. This returns
false for a link to a nonexistent target. The script then reads the proposed
version, transfer method, URL, and target list from the selected codec's
software information response. For an update, it uses the same fixed
destination for both supported transfer methods:

```text
rsync -a ... <codec URL> /upgrade/pkg
curl ... <codec URL> -o /upgrade/pkg
```

`rsync -a` preserves a supplied symbolic link. The first transfer placed a
link at `/upgrade/pkg` pointing to a previously nonexistent file under
`/etc/profile.d`. On the next run, the regular-file check still did not see
an occupied package path. `curl -o` opened `/upgrade/pkg`, followed the link,
and created the target file with root privileges. A later `swsync` invocation
sourced `/etc/profile`, which loaded the new profile file and ran its contents
as root.

The confirmed primitive is **creation of a root-owned file at an
attacker-chosen, previously nonexistent path**. The regular-file check blocks
this exact sequence when the symlink points to an existing regular file; an
overwrite of such a file was not demonstrated. The proof target was in the
panel's RAM-backed root filesystem, so persistence across reboot was not
established.

The defect is in Cisco's privileged updater path handling. The observed
`rsync` and `curl` behavior follows their normal symlink semantics; this is
not an identified vulnerability in either upstream tool. The write occurs
before firmware package signature verification. No signed or unsigned
firmware package was served or installed during the test.

## Validation

The exact ARM `rsync` 2.6.9 and `curl` 7.66.0 clients were first tested
off-device: the former created the dangling link and the latter created its
target outside the download directory. An isolated live test then selected
the controlled codec on the panel. The panel support log recorded the
`/upgrade/pkg` link to the temporary profile file. After the HTTP transfer,
the subsequent root execution returned `uid=0(root) gid=0(root)` from `id`.

The temporary proof file and symlink were removed after validation, and the
panel returned to its normal screen after a power cycle.

## Impact and risk reduction

A party able to control the selected codec's update response can cause the
affected panel to create a file outside its upgrade directory with root
privileges. On the tested build, placing that file in the root-sourced profile
directory led to root code execution. The test did not show that a remote
Internet attacker can reach this path, that an existing trusted pairing can
be impersonated, or that later firmware remains affected.

No fixed Touch 10 release has been verified for this issue. Restricting the
panel to trusted codec endpoints and preventing selection of untrusted codecs
reduces exposure. Replacing unsupported Touch 10 hardware is the longer-term
option. These measures are risk reduction, not a verified software fix.

## Disclosure status and related advisories

The live validation took place on 7 November 2026. This advisory was first
published on 9 November 2026. At publication, the finding had not been
reported directly to Cisco and no CVE had been assigned to it.

Cisco's [CVE-2020-3336 advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tp-cmd-inj-7ZpWhvZb)
describes authenticated upgrade command injection. Its
[2023 RoomOS file-write advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-roomos-file-write-rHKwegKf)
describes local support-account symlink issues. Neither public description
identifies this selected-codec, two-transfer `swsync` chain. Whether a CVE
record would be considered a duplicate is for an assigning CNA to decide.

Cisco has published end-of-support notices for
[older Touch 10 SKUs](https://www.cisco.com/c/en/us/products/collateral/collaboration-endpoints/telepresence-touch/eos-eol-notice-c51-743205.html)
and [CS-TOUCH10](https://www.cisco.com/c/en/us/products/collateral/collaboration-endpoints/telepresence-touch/eos-eol-notice-c51-744790.pdf).
These notices apply to different hardware SKUs; no specific support date is
attributed to the test unit while its SKU remains unverified.
