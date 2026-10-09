from pathlib import Path
import markdown

root = Path(__file__).resolve().parent.parent
src = root / "README.md"
dst = root / "README_preview.html"

html = markdown.markdown(
    src.read_text(encoding="utf-8"),
    extensions=["fenced_code", "tables"],
)

dst.write_text(
    f"<html><head><meta charset='utf-8'>"
    f"<style>body{{font-family:sans-serif;max-width:800px;margin:20px auto;}}"
    f"pre{{background:#f4f4f4;padding:10px;border-radius:4px;}}"
    f"code{{background:#f4f4f4;padding:2px;}}</style>"
    f"</head><body>{html}</body></html>",
    encoding="utf-8",
)
print(f"Готово: {dst}")
print("Откройте этот файл в браузере.")