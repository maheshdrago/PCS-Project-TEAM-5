from DB_SERVER import app
from DB_SERVER.routes import *


if __name__=="__main__":
    app.run(debug=True)