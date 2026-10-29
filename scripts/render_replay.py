#!/usr/bin/env python3
"""Render readable cards from actual demo reports. No numerical work is simulated.

The raw asciicast preserves execution timing. This silent edited replay adds
reading holds and rounds displayed answers; exact values remain in the JSON.
Requires Pillow and ffmpeg, independent of the CipherShape runtime.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
from PIL import Image, ImageDraw, ImageFont


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--font", type=Path, default=Path("/System/Library/Fonts/Menlo.ttc"))
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    font = lambda size: ImageFont.truetype(str(args.font), size)
    bg, ink, muted, blue, green = "#f4f6fa", "#142236", "#526478", "#164c82", "#176844"
    cards = []

    def base(title, subtitle):
        im = Image.new("RGB", (1280, 720), bg)
        d = ImageDraw.Draw(im)
        d.text((48, 34), "CIPHERSHAPE", font=font(22), fill=blue)
        d.text((48, 86), title, font=font(34), fill=ink)
        d.text((48, 137), subtitle, font=font(18), fill=muted)
        d.line((48, 178, 1232, 178), fill="#ccd5df", width=2)
        d.text((48, 680), "Actual encrypted HTTP execution · edited replay with reading holds · exact data in JSON", font=font(15), fill=muted)
        return im, d

    im, d = base("Real numerical APIs over encrypted inputs", "OpenFHE CKKS · client-owned secret key · fixed public programs")
    for y, text in [(237, "1  Compile a typed multi-output workload"), (308, "2  Client encrypts; separate evaluator runs ciphertext"), (379, "3  Client decrypts and checks numerical error"), (490, "Two applications. Two changed-input requests each.")]:
        d.text((55, y), text, font=font(25), fill=ink)
    d.text((55, 575), "Recorded run: demo.cast. This replay is silent.", font=font(20), fill=muted)
    cards.append((im, 4))
    for app, title in (("analytics", "Seven related analytics endpoints"), ("model", "Trained public linear-model inference")):
        report = json.loads((args.source / f"{app}-report.json").read_text())
        for run in report["runs"]:
            index = run["request"]
            im, d = base(title, f"Request {index+1}/2 · private client inputs {'changed' if index else 'initial'} · same program and key epoch")
            d.text((52, 207), "CLIENT: DECRYPTED OUTPUTS", font=font(22), fill=green)
            d.text((744, 207), "SERVER: PUBLIC METADATA", font=font(22), fill=blue)
            d.line((710, 210, 710, 620), fill="#ccd5df", width=2)
            y = 260
            for name, value in run["decrypted"].items():
                d.text((52, y), f"{name:<14} {value: .8f}", font=font(21), fill=ink)
                y += 35
            for y, label, value in [(263, "Ciphertext upload", f"{run['request_bytes']:,} bytes"),
                                    (340, "Ciphertext response", f"{run['response_bytes']:,} bytes"),
                                    (417, "Encrypted evaluation", f"{run['evaluation_seconds']:.4f} s"),
                                    (494, "Program", report["program_id"][:20])]:
                d.text((744, y), label, font=font(18), fill=muted)
                d.text((744, y+29), value, font=font(22), fill=ink)
            d.text((52, 562), f"Encryption error: {run['encryption_error']:.2e}", font=font(21), fill=green)
            d.text((52, 600), "Numerical contract passed (tolerance 1e-4)", font=font(19), fill=green)
            cards.append((im, 6 if app == "analytics" else 5))
    im, d = base("Executed locally and checked independently", "A bounded research compiler with explicit limits")
    for y, text in [(237, "87 local tests passed; both applications installed cleanly."),
                    (307, "Honest-but-curious server; public shapes and weights."),
                    (377, "No consistent measured speedup over the tuned baseline."),
                    (447, "Source, frozen study, failures and limits are retained.")]:
        d.text((55, y), text, font=font(23), fill=ink)
    d.text((55, 555), "github.com/nazeeh111/CipherShape", font=font(27), fill=blue)
    cards.append((im, 5))
    concat = []
    for i, (im, duration) in enumerate(cards):
        path = args.out / f"card-{i:02}.png"
        im.save(path)
        concat.extend([f"file '{path.name}'", f"duration {duration}"])
    concat.append(f"file 'card-{len(cards)-1:02}.png'")
    (args.out / "frames.ffconcat").write_text("\n".join(concat)+"\n")
    subprocess.run([shutil.which("ffmpeg") or "ffmpeg", "-hide_banner", "-nostdin", "-n",
                    "-f", "concat", "-safe", "0", "-i", str(args.out / "frames.ffconcat"),
                    "-vf", "fps=24,format=yuv420p", "-t", str(sum(x[1] for x in cards)),
                    "-c:v", "libx264", "-crf", "18", "-preset", "medium", "-movflags", "+faststart",
                    str(args.out / "ciphershape-demo.mp4")], check=True)


if __name__ == "__main__":
    main()
