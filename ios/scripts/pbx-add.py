#!/usr/bin/env python3
"""Зарегистрировать файлы overlay в SimpleX.xcodeproj — идемпотентно.

Проект upstream в классическом формате (objectVersion 55): Xcode видит только файлы,
перечисленные в project.pbxproj. Разложить overlay по каталогам мало — без записи в
проекте файл молча не попадёт в сборку, и это та же ошибка, что однажды случилась с
Android-форком, только ещё тише.

Идентификаторы выводятся из пути файла (md5), поэтому повторный запуск ничего не
меняет, а ребейз даёт те же строки, что и прошлый раз.

    pbx-add.py <project.pbxproj> <target> <sources|resources> <group-path> <file>...

group-path — путь группы от корня проекта (`SimpleXChat/Hearth`); недостающая
последняя группа создаётся, промежуточные обязаны существовать.
"""
import hashlib
import re
import sys

FILE_TYPES = {
    ".swift": "sourcecode.swift",
    ".json": "text.json",
    ".pem": "text",
}


def pbx_id(*parts: str) -> str:
    return hashlib.md5(("hearth:" + ":".join(parts)).encode()).hexdigest()[:24].upper()


def block(text: str, obj_id: str) -> tuple[int, int]:
    """Границы объекта `ID /* … */ = { … };` — от начала строки до закрывающей `};`."""
    m = re.search(r"^\t\t" + obj_id + r" (/\*.*?\*/ )?= \{", text, re.M)
    if not m:
        raise SystemExit(f"нет объекта {obj_id}")
    depth, i = 0, m.end() - 1
    while True:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return m.start(), i + 2  # "};"
        i += 1


def insert_into_list(text: str, obj_id: str, key: str, entry: str) -> str:
    start, end = block(text, obj_id)
    body = text[start:end]
    m = re.search(r"\b" + key + r" = \(\n", body)
    if not m:
        raise SystemExit(f"у {obj_id} нет списка {key}")
    pos = start + m.end()
    return text[:pos] + entry + text[pos:]


def insert_object(text: str, section: str, entry: str) -> str:
    marker = f"/* Begin {section} section */\n"
    pos = text.find(marker)
    if pos < 0:
        raise SystemExit(f"нет секции {section}")
    pos += len(marker)
    return text[:pos] + entry + text[pos:]


def find_group(text: str, parent_id: str, name: str) -> str | None:
    start, end = block(text, parent_id)
    children = re.search(r"children = \((.*?)\);", text[start:end], re.S)
    for child in re.findall(r"([0-9A-F]{24})", children.group(1) if children else ""):
        cs, ce = block(text, child)
        obj = text[cs:ce]
        if "isa = PBXGroup;" in obj and re.search(r"\b(path|name) = \"?" + re.escape(name) + r"\"?;", obj):
            return child
    return None


def main_group(text: str) -> str:
    return re.search(r"mainGroup = ([0-9A-F]{24})", text).group(1)


def target_phase(text: str, target: str, phase: str) -> str:
    for m in re.finditer(r"^\t\t([0-9A-F]{24}) /\* .*? \*/ = \{\n\t\t\tisa = PBXNativeTarget;", text, re.M):
        s, e = block(text, m.group(1))
        obj = text[s:e]
        if re.search(r"\bname = \"?" + re.escape(target) + r"\"?;", obj):
            pm = re.search(r"([0-9A-F]{24}) /\* " + phase + r" \*/", obj)
            if not pm:
                raise SystemExit(f"у цели {target} нет фазы {phase}")
            return pm.group(1)
    raise SystemExit(f"нет цели {target}")


def main() -> None:
    if len(sys.argv) < 6:
        raise SystemExit(__doc__)
    path, target, kind, group_path, files = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
    phase = {"sources": "Sources", "resources": "Resources"}[kind]
    text = open(path, encoding="utf-8").read()

    group = main_group(text)
    names = group_path.split("/")
    for depth, name in enumerate(names):
        found = find_group(text, group, name)
        if found is None:
            if depth != len(names) - 1:
                raise SystemExit(f"нет группы {'/'.join(names[:depth + 1])}")
            found = pbx_id("group", group_path)
            text = insert_object(text, "PBXGroup",
                                 f"\t\t{found} /* {name} */ = {{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n"
                                 f"\t\t\t);\n\t\t\tpath = {name};\n\t\t\tsourceTree = \"<group>\";\n\t\t}};\n")
            text = insert_into_list(text, group, "children", f"\t\t\t\t{found} /* {name} */,\n")
        group = found

    phase_id = target_phase(text, target, phase)
    added = 0
    for f in files:
        name = f.rsplit("/", 1)[-1]
        ext = "." + name.rsplit(".", 1)[-1]
        ref = pbx_id("ref", group_path, name)
        build = pbx_id("build", target, group_path, name)
        if ref not in text:
            text = insert_object(text, "PBXFileReference",
                                 f"\t\t{ref} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = "
                                 f"{FILE_TYPES.get(ext, 'text')}; path = {name}; sourceTree = \"<group>\"; }};\n")
            text = insert_into_list(text, group, "children", f"\t\t\t\t{ref} /* {name} */,\n")
        if build not in text:
            text = insert_object(text, "PBXBuildFile",
                                 f"\t\t{build} /* {name} in {phase} */ = {{isa = PBXBuildFile; fileRef = {ref} /* {name} */; }};\n")
            text = insert_into_list(text, phase_id, "files", f"\t\t\t\t{build} /* {name} in {phase} */,\n")
            added += 1
    open(path, "w", encoding="utf-8").write(text)
    print(f"  {target}/{phase}: добавлено {added}, всего в списке {len(files)}")


if __name__ == "__main__":
    main()
