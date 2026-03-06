#!/usr/bin/env python3
"""PRICING_GUIDE.md → DOCX 변환 스크립트
Mermaid 다이어그램을 PNG로 렌더링한 후 pandoc으로 DOCX 생성
"""
import re
import subprocess
import tempfile
import shutil
from pathlib import Path

WORKSPACE = Path("/Users/hyuksun.choi/works/web-risk")
MD_INPUT = WORKSPACE / "PRICING_GUIDE.md"
DOCX_OUTPUT = WORKSPACE / "PRICING_GUIDE.docx"
MMDC = WORKSPACE / "node_modules" / ".bin" / "mmdc"
IMG_DIR = WORKSPACE / "mermaid_images"


def extract_and_render_mermaid(md_text: str) -> str:
    """Mermaid 블록을 PNG로 렌더링하고 이미지 참조로 교체"""
    IMG_DIR.mkdir(exist_ok=True)

    pattern = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)
    matches = list(pattern.finditer(md_text))

    if not matches:
        print("Mermaid 블록 없음")
        return md_text

    print(f"Mermaid 블록 {len(matches)}개 발견")

    for i, match in enumerate(reversed(matches)):
        idx = len(matches) - 1 - i  # 뒤에서부터 교체 (offset 유지)
        mermaid_code = match.group(1).strip()
        img_name = f"diagram_{idx + 1}.png"
        img_path = IMG_DIR / img_name

        # .mmd 파일 작성
        mmd_file = IMG_DIR / f"diagram_{idx + 1}.mmd"
        mmd_file.write_text(mermaid_code, encoding="utf-8")

        # mmdc로 PNG 렌더링
        print(f"  [{idx + 1}/{len(matches)}] 렌더링 중: {img_name}")
        result = subprocess.run(
            [str(MMDC), "-i", str(mmd_file), "-o", str(img_path),
             "-b", "white", "-w", "1200", "-s", "2"],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0 or not img_path.exists():
            print(f"    ⚠️  렌더링 실패, 텍스트 플레이스홀더로 대체")
            print(f"    stderr: {result.stderr[:200]}")
            # 실패 시 코드블록으로 유지
            replacement = f"\n\n> *[다이어그램 {idx + 1} — Mermaid 렌더링 필요]*\n\n"
        else:
            print(f"    ✅ 성공: {img_path}")
            replacement = f"\n\n![다이어그램 {idx + 1}]({img_path})\n\n"

        md_text = md_text[:match.start()] + replacement + md_text[match.end():]

    return md_text


def convert_details_tags(md_text: str) -> str:
    """<details>/<summary> → 일반 헤딩으로 변환 (Google Docs 호환)"""
    md_text = re.sub(
        r"<details>\s*<summary><b>(.*?)</b></summary>",
        r"\n**\1**\n",
        md_text
    )
    md_text = re.sub(
        r"<details>\s*<summary>(.*?)</summary>",
        r"\n**\1**\n",
        md_text
    )
    md_text = md_text.replace("</details>", "")
    return md_text


def main():
    print("=" * 50)
    print("PRICING_GUIDE.md → DOCX 변환")
    print("=" * 50)

    md_text = MD_INPUT.read_text(encoding="utf-8")

    # 1. Mermaid → PNG
    md_text = extract_and_render_mermaid(md_text)

    # 2. <details> → 일반 텍스트
    md_text = convert_details_tags(md_text)

    # 3. 임시 MD 파일 저장
    tmp_md = WORKSPACE / "_PRICING_GUIDE_processed.md"
    tmp_md.write_text(md_text, encoding="utf-8")

    # 4. pandoc으로 DOCX 변환
    print(f"\npandoc 변환 중...")
    result = subprocess.run(
        ["pandoc", str(tmp_md),
         "-o", str(DOCX_OUTPUT),
         "--from", "markdown",
         "--to", "docx",
         "--toc",                    # 목차 자동 생성
         "--toc-depth=3",
         "--highlight-style=tango",  # 코드 블록 스타일
         ],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        print(f"❌ pandoc 실패: {result.stderr}")
        return

    # 5. 정리
    tmp_md.unlink()
    print(f"\n✅ 변환 완료: {DOCX_OUTPUT}")
    print(f"   파일 크기: {DOCX_OUTPUT.stat().st_size / 1024:.1f} KB")
    print(f"\n📋 사용법: Google Drive에 업로드 → Google Docs로 열기")

    # mermaid_images 폴더는 유지 (확인용)
    if IMG_DIR.exists():
        pngs = list(IMG_DIR.glob("*.png"))
        print(f"   렌더링된 이미지: {len(pngs)}개 (mermaid_images/ 폴더)")


if __name__ == "__main__":
    main()
