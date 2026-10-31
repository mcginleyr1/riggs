// SSH-backdoor implants: plant an operator key in authorized_keys, then open a
// reverse tunnel so the operator can reach this host's sshd from outside.
// Modeled on the 2026-10 backdoored Claude Code VS Code extension (Cursor
// Marketplace 2.1.312 / 2.1.313):
// https://phorion.io/blog/offical-claude-code-vsx-compromise/

import "hash"

rule SSH_Backdoor_Reverse_Tunnel_Implant {
    meta:
        id = "RIGGS-YARA-001"
        description = "Plants an SSH public key in authorized_keys and opens a reverse tunnel to local sshd with host-key checking overridden"
        severity = "critical"
        mitre = "T1098.004, T1572"
        author = "riggs-team"
        created = "2026-10-31"

    strings:
        $authorized_keys = "authorized_keys"
        // OpenSSH key type names; ECDSA ones carry no "ssh-" prefix.
        $pubkey = /(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) AAAA[0-9A-Za-z+\/]{40}/
        $hostkey_strict = "StrictHostKeyChecking" nocase
        $hostkey_known_hosts = "UserKnownHostsFile" nocase
        $fwd_to_sshd_localhost = "localhost:22"
        $fwd_to_sshd_loopback = "127.0.0.1:22"
        $fwd_to_sshd_loopback6 = "::1]:22"
        $exit_on_forward_failure = "ExitOnForwardFailure" nocase

    condition:
        $authorized_keys and $pubkey and any of ($hostkey_*)
        and (any of ($fwd_to_sshd_*) or $exit_on_forward_failure)
}

rule ClaudeCode_VSX_Backdoor_2026_10 {
    meta:
        id = "RIGGS-YARA-002"
        description = "Backdoored Claude Code VS Code extension (2026-10) or the tunnel script, key and LaunchAgent it drops"
        severity = "critical"
        mitre = "T1195.002"
        author = "riggs-team"
        created = "2026-10-31"
        reference = "https://phorion.io/blog/offical-claude-code-vsx-compromise/"

    // Hex, so this file (and riggs's own source/build output) doesn't match it.
    strings:
        $tunnel_host = { 31 33 34 2E 32 30 39 2E 38 32 2E 32 32 35 }          // 134.209.82[.]225
        $key_comment = { 73 76 63 2D 74 65 6C 65 6D 65 74 72 79 }             // svc[-]telemetry(-tun)
        $launchagent_label = { 63 6F 6D 2E 61 70 70 6C 65 2E 73 79 73 6D 6F 6E 64 } // com[.]apple[.]sysmond
        $tunnel_key_tmp = { 2E 73 74 6B 5F }                                   // [.]stk_
        $dropped_script = { 2F 2E 63 6F 6E 66 69 67 2F 2E 73 6D 74 }          // /[.]config/[.]smt(k)
        $dropped_key = { 2E 73 6D 74 6B }                                      // [.]smtk
        $dropped_cmd = { 73 6D 74 2E 63 6D 64 }                                // smt[.]cmd
        $startup_cmd = { 73 79 73 6D 6F 6E 2E 63 6D 64 }                       // sysmon[.]cmd

    // Never one string alone: a Malicious hit quarantines the file, and an
    // analyst's notes or shell history holding just the IP must survive.
    // (The IOC list still flags the IP on command lines and connections.)
    condition:
        hash.sha256(0, filesize) == "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
        or 2 of them
}
