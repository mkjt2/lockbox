from flask import Flask, request

app = Flask(__name__)


@app.route("/", methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
def catch_all(subpath: str = ""):
    return {
        "subpath": subpath,
        "args": request.args,
        "headers": dict(request.headers),
        "form": request.form,
        "data": request.data.decode("utf-8"),
    }
