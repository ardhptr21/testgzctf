#!/usr/bin/env python3
from flask import Flask, render_template_string, request

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Simple Web</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: system-ui, sans-serif;
      background: #f4f7f2;
      color: #172018;
    }
    main {
      width: min(680px, calc(100vw - 32px));
    }
    h1 {
      font-size: 28px;
      margin: 0 0 12px;
    }
    p {
      line-height: 1.5;
    }
    form {
      display: grid;
      gap: 12px;
      margin-top: 24px;
    }
    input, textarea, button {
      font: inherit;
      border: 1px solid #9bac9d;
      border-radius: 6px;
      padding: 10px 12px;
    }
    textarea {
      min-height: 130px;
      resize: vertical;
    }
    button {
      width: fit-content;
      border-color: #245c3a;
      background: #245c3a;
      color: white;
      cursor: pointer;
    }
    .preview {
      margin-top: 24px;
      padding-top: 18px;
      border-top: 1px solid #c8d4c9;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <main>
    <h1>Greeting Preview</h1>
    <p>Create a short message template for a guest. The preview will render it with the guest name.</p>
    <form method="post" action="/preview">
      <input name="name" placeholder="Guest name" value="{{ name }}" maxlength="80">
      <textarea name="template" placeholder="Hello {{ name }}!">{{ template }}</textarea>
      <button type="submit">Preview</button>
    </form>
    {% if preview is not none %}
    <section class="preview">
      <strong>Preview</strong>
      <div>{{ preview }}</div>
    </section>
    {% endif %}
  </main>
</body>
</html>"""


@app.get("/")
def index():
    return render_template_string(PAGE, name="friend", template="Hello {{ name }}!", preview=None)


@app.post("/preview")
def preview():
    name = request.form.get("name", "friend")[:80]
    template = request.form.get("template", "")
    rendered = render_template_string(template, name=name)
    return render_template_string(PAGE, name=name, template=template, preview=rendered)


@app.get("/health")
def health():
    return "ok\n", 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
