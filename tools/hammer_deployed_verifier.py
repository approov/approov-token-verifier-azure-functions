#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import jwt


AUTHORIZATION = "Bearer verifier-hammer-token"
METHOD = "POST"
SCHEME = "https"
HOST = "api.example.com"
PATH = "/token"
QUERY = "?param=value"
BODY = b'{"ok":true}'


@dataclass
class Result:
    name: str
    expected_status: int
    status: int
    reason_code: Optional[str]
    ok: bool
    body: str


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sha256_b64(text: str) -> str:
    return b64(hashlib.sha256(text.encode("utf-8")).digest())


def generate_installation_key(tmp: Path) -> Tuple[Path, str]:
    private_key = tmp / "install-private.pem"
    public_der = tmp / "install-public.der"
    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(private_key)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "ec", "-in", str(private_key), "-pubout", "-outform", "DER", "-out", str(public_der)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return private_key, b64(public_der.read_bytes())


def der_ecdsa_to_raw(der: bytes, field_size: int = 32) -> bytes:
    if len(der) < 8 or der[0] != 0x30:
        raise ValueError("not an ECDSA DER sequence")
    idx = 2
    if der[1] & 0x80:
        length_octets = der[1] & 0x7F
        idx = 2 + length_octets
    if der[idx] != 0x02:
        raise ValueError("missing r integer")
    r_len = der[idx + 1]
    r = der[idx + 2 : idx + 2 + r_len]
    idx = idx + 2 + r_len
    if der[idx] != 0x02:
        raise ValueError("missing s integer")
    s_len = der[idx + 1]
    s = der[idx + 2 : idx + 2 + s_len]
    return r[-field_size:].rjust(field_size, b"\x00") + s[-field_size:].rjust(field_size, b"\x00")


def sign_message(private_key: Path, message: str) -> str:
    with tempfile.NamedTemporaryFile() as payload, tempfile.NamedTemporaryFile() as sig:
        payload.write(message.encode("utf-8"))
        payload.flush()
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", sig.name, payload.name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return b64(der_ecdsa_to_raw(Path(sig.name).read_bytes()))


def sign_rsa_jwt(signing_input: str, private_key: Path) -> str:
    with tempfile.NamedTemporaryFile() as payload, tempfile.NamedTemporaryFile() as sig:
        payload.write(signing_input.encode("ascii"))
        payload.flush()
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", sig.name, payload.name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return b64url(Path(sig.name).read_bytes())


def create_token(
    secret: str,
    ipk: str,
    *,
    expires_delta: int = 600,
    authorization: str = AUTHORIZATION,
    wrong_secret: bool = False,
    alg: str = "HS256",
    rsa_private_key: Optional[Path] = None,
) -> str:
    now = int(time.time())
    payload = {
        "did": "HammerDevice",
        "pay": sha256_b64(authorization),
        "ipk": ipk,
        "iat": now - 60,
        "nbf": now - 60,
        "exp": now + expires_delta,
    }
    if alg == "RS256":
        if rsa_private_key is None:
            raise ValueError("RS256 token generation requires --rsa-private-key")
        signing_input = b64url(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
        signing_input += "." + b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        return signing_input + "." + sign_rsa_jwt(signing_input, rsa_private_key)

    key = base64.b64decode(secret)
    if wrong_secret:
        key = b"wrong-secret-for-negative-test-123456"
    return jwt.encode(payload, key, algorithm=alg)


def content_digest(body: bytes) -> str:
    return "sha-256=:" + b64(hashlib.sha256(body).digest()) + ":"


def canonical_lines(headers: dict, components: List[str]) -> str:
    values = {
        "@method": METHOD,
        "@target-uri": f"{SCHEME}://{HOST}{PATH}{QUERY}",
        "@authority": HOST,
        "@scheme": SCHEME,
        "@path": PATH,
        "@query": QUERY,
        "@request-target": PATH + QUERY,
        "authorization": headers.get("Authorization", ""),
        "content-digest": headers.get("Content-Digest", ""),
        "approov-token": headers.get("Approov-Token", ""),
    }
    lines = [f'"{component}": {values[component]}' for component in components]
    return "\n".join(lines)


def build_headers(
    private_key: Path,
    token: Optional[str],
    *,
    body: bytes = BODY,
    authorization: str = AUTHORIZATION,
    include_signature: bool = True,
    include_signature_input: bool = True,
    include_digest: bool = True,
    sign_digest: bool = True,
    sign_query: bool = False,
    created_offset: int = -30,
    tamper_signature: bool = False,
) -> dict:
    headers = {
        "X-Approov-Original-Method": METHOD,
        "X-Approov-Original-Scheme": SCHEME,
        "X-Approov-Original-Host": HOST,
        "X-Approov-Original-Path": PATH,
        "X-Approov-Original-Query": QUERY,
        "Authorization": authorization,
    }
    if token is not None:
        headers["Approov-Token"] = token
    if include_digest:
        headers["Content-Digest"] = content_digest(body)

    components = ["@method", "@target-uri", "authorization", "approov-token"]
    if sign_query:
        components.insert(2, "@query")
    if include_digest and sign_digest:
        components.insert(-1, "content-digest")

    created = int(time.time()) + created_offset
    expires = created + 600
    component_list = " ".join(f'"{component}"' for component in components)
    signature_input = f'install=({component_list});alg="ecdsa-p256-sha256";created={created};expires={expires}'
    if include_signature_input:
        headers["Signature-Input"] = signature_input

    if include_signature:
        signature_base = canonical_lines(headers, components) + "\n" + f'"@signature-params": ' + signature_input.split("=", 1)[1]
        signature = "AAAA" if tamper_signature else sign_message(private_key, signature_base)
        headers["Signature"] = f"install=:{signature}:"

    return headers


def send(url: str, headers: dict, body: bytes = BODY) -> Tuple[int, str]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def run_case(name: str, expected_status: int, expected_reason: Optional[str], url: str, headers: dict, body: bytes = BODY) -> Result:
    status, response_body = send(url, headers, body)
    try:
        parsed = json.loads(response_body)
    except json.JSONDecodeError:
        parsed = {}
    reason = parsed.get("reasonCode")
    ok = status == expected_status and (expected_reason is None or reason == expected_reason)
    return Result(name, expected_status, status, reason, ok, response_body)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--secret-base64", required=True)
    parser.add_argument("--iterations", type=int, default=25)
    parser.add_argument("--jwt-alg", default="HS256", choices=["HS256", "RS256"])
    parser.add_argument("--rsa-private-key")
    args = parser.parse_args()

    results: List[Result] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        private_key, ipk = generate_installation_key(Path(tmpdir))
        rsa_private_key = Path(args.rsa_private_key) if args.rsa_private_key else None
        valid_token = create_token(args.secret_base64, ipk, alg=args.jwt_alg, rsa_private_key=rsa_private_key)

        results.append(run_case("valid signed digest", 200, "approov_valid", args.url, build_headers(private_key, valid_token)))
        results.append(run_case("missing token", 401, "missing_approov_token", args.url, build_headers(private_key, None)))
        results.append(run_case("malformed token", 401, "invalid_approov_token", args.url, build_headers(private_key, "not-a-jwt")))
        results.append(run_case("expired token", 401, "expired_approov_token", args.url, build_headers(private_key, create_token(args.secret_base64, ipk, expires_delta=-60, alg=args.jwt_alg, rsa_private_key=rsa_private_key))))
        if args.jwt_alg == "HS256":
            results.append(run_case("wrong token hmac", 401, "invalid_approov_token_signature", args.url, build_headers(private_key, create_token(args.secret_base64, ipk, wrong_secret=True))))
            results.append(run_case("unconfigured jwt alg", 401, "invalid_approov_token_algorithm", args.url, build_headers(private_key, create_token(args.secret_base64, ipk, alg="HS384"))))
        results.append(run_case("wrong token binding", 401, "invalid_token_binding", args.url, build_headers(private_key, valid_token, authorization="Bearer changed")))
        results.append(run_case("missing signature", 401, "missing_message_signature", args.url, build_headers(private_key, valid_token, include_signature=False)))
        results.append(run_case("tampered signature", 401, "invalid_message_signature", args.url, build_headers(private_key, valid_token, tamper_signature=True)))
        results.append(run_case("unsigned content digest", 401, "invalid_message_signature", args.url, build_headers(private_key, valid_token, sign_digest=False)))
        results.append(run_case("future signature", 401, "invalid_message_signature", args.url, build_headers(private_key, valid_token, created_offset=3600)))
        results.append(run_case("stale signature", 401, "invalid_message_signature", args.url, build_headers(private_key, valid_token, created_offset=-3600)))
        results.append(run_case("valid with @query", 200, "approov_valid", args.url, build_headers(private_key, valid_token, sign_query=True)))

        signed_headers = build_headers(private_key, valid_token)
        results.append(run_case("tampered body", 401, "invalid_message_signature", args.url, signed_headers, b'{"ok":false}'))

        for i in range(args.iterations):
            results.append(run_case(f"hammer valid {i + 1}", 200, "approov_valid", args.url, build_headers(private_key, valid_token)))

    for result in results:
        marker = "PASS" if result.ok else "FAIL"
        print(f"{marker:4} {result.name:24} expected={result.expected_status} actual={result.status} reason={result.reason_code}")
        if not result.ok:
            print(result.body)

    passed = sum(1 for result in results if result.ok)
    print(f"SUMMARY passed={passed} failed={len(results) - passed} total={len(results)}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
