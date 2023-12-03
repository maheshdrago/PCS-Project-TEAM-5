from DB_SERVER import app, db
from DB_SERVER.models import Users, ChunkMappings, ChunkFileMappings, Permissions, Keys
from flask import request, jsonify


@app.route("/register", methods=['POST'])
def register():
    try:
        data = request.json
        username = data['username']
        password = data['password']

        user = Users(username=username, password=password)
        db.session.add(user)
        db.session.commit()

        return "User with Username : {} Registerd Successfully".format(username)
    except Exception as e:
        print(str(e.args))
        return

@app.route("/login", methods=["GET"])
def login():
    username = request.args.get('username')
    password = request.args.get("password")

    user = Users.query.filter_by(username=username).first()

    if user and user.password==password:
        return "Success"
    else:
        return "Fail"
    
@app.route("/addChunkMapping", methods=["POST", "PATCH"])
def chunkMapping():
    if request.method == "POST":
        try:
            data = request.json
            pieces = data["pieces"]
            filename = data["filename"]
            mapping_objs = []
            
            fileMapping = ChunkFileMappings(filename=filename)
            db.session.add(fileMapping)

            for piece in pieces:
                chunk_peer = piece["chunk_peer"]
                chunk_number = piece["chunk_number"]
                chunk_id = piece["chunk_id"]

                mapping = ChunkMappings(chunk_number=chunk_number, chunk_id=chunk_id, chunk_peer=chunk_peer, chunkfilemappings=fileMapping)
                mapping_objs.append(mapping)

            
            db.session.add_all(mapping_objs)
            db.session.commit()

            return "Success"
        except Exception as e:
            return str(e.args)
    else:
        try:
            data = request.json
            pieces = data["pieces"]
            filename = data["filename"]
            mapping_objs = []
            
            fileMapping = ChunkFileMappings.query.filter_by(filename=filename).first()

            for piece in pieces:
                chunk_peer = piece["chunk_peer"]
                chunk_number = piece["chunk_number"]
                chunk_id = piece["chunk_id"]

                mapping = ChunkMappings(chunk_number=chunk_number, chunk_id=chunk_id, chunk_peer=chunk_peer, chunkfilemappings=fileMapping)
                mapping_objs.append(mapping)

            
            db.session.add_all(mapping_objs)
            db.session.commit()

            return "Success"
        except Exception as e:
            return str(e.args)

    

@app.route("/retrieveChunks",methods=["GET"])
def retrieveChunks():
    try:
        filename = request.args.get('filename')
        fileMapping = ChunkFileMappings.query.filter_by(filename=filename).first()
        print(fileMapping)
        if fileMapping:
            chunks = fileMapping.mappings
            
            pieces = []

            for i in chunks:
                pieces.append({
                    "chunk_peer":i.chunk_peer,
                    "chunk_number":i.chunk_number,
                    "chunk_id":i.chunk_id
                })
            
            return jsonify({
                "status":"success",
                "chunks":pieces
            })
        else:
            return jsonify({
                "status":"File not Found"
            })
    except Exception as e:
        return str(e.args)

@app.route("/deleteChunks", methods=["GET"])
def deleteChunks():
    try:
        filename = request.args.get('filename')

        fileMapping = ChunkFileMappings.query.filter_by(filename=filename).first()
        if fileMapping:
            chunks = fileMapping.mappings

            pieces = []

            for i in chunks:
                pieces.append({
                    "chunk_peer":i.chunk_peer,
                    "chunk_number":i.chunk_number,
                    "chunk_id":i.chunk_id
                })
            
            db.session.delete(fileMapping)
            db.session.commit()

            return jsonify({
                "status":"success",
                "chunks":pieces
            })
        
        else:
            return jsonify({
                "status":"File not Found"
            })
    except Exception as e:
        return str(e.args)
    
@app.route("/chunkNumber", methods=["GET"])
def chunkNumber():
    try:
        filename = request.args.get("filename")

        fileMapping = ChunkFileMappings.query.filter_by(filename=filename).first()

        if fileMapping:
            chunks = fileMapping.mappings

            return jsonify({
                "status":"success",
                "number": len(chunks)
            })
        
        else:
            return jsonify({
                "status":"File not Found"
            })
        
    except Exception as e:
        return str(e.args)


@app.route("/userValid", methods=["GET"])
def userValid():
    try:
        username = request.args.get("username")

        user = Users.query.filter_by(username=username).first()

        if user:
            return jsonify({
                "status":"Success",
            })
        
        else:
            return jsonify({
                "status":"File not Found"
            })
        
    except Exception as e:
        return str(e.args)

@app.route("/addPermissions", methods=["POST"])
def addPermissions():
    try:
        data = request.json
        filename = data['filename']
        permissions = data['permissions']
        username = data['username']

        permission = Permissions(filename=filename, permissions=permissions, username=username)

        db.session.add(permission)
        db.session.commit()
        
        return jsonify({
            "status":"Success",
        })
        
    except Exception as e:
        print(str(e.args))
        return jsonify({
            "status":str(e.args),
        })

@app.route("/queryPermissions", methods=["GET"])
def queryPermissions():
    try:
        username = request.args.get("username")
        permission = request.args.get('permission')
        filename = request.args.get('filename')

        permission_obj = Permissions.query.filter_by(username=username, filename=filename).first()
        permissions = permission_obj.permissions.split(",")

        if permission in permissions:
            return jsonify({
                "status":"Success",
            })
        
        else:
            return jsonify({
                "status":"Fail"
            })
        
    except Exception as e:
        return str(e.args)

@app.route("/checkUsername", methods=["GET"])
def checkUsername():
    try:
        username = request.args.get("username")

        user = Users.query.filter_by(username=username).first()

        if not user:
            return jsonify({
                "status":"Success",
            })
        
        else:
            return jsonify({
                "status":"Fail"
            })
        
    except Exception as e:
        return str(e.args)

@app.route("/addKeys", methods=["POST"])
def addKeys():
    try:
        data = request.json
        username = data['username']
        public_key = data['public_key']
        private_key = data['private_key']

        user = Users.query.filter_by(username=username).first()

        if user:
            keys_obj = Keys(public_key=public_key, private_key=private_key, user=user)
            db.session.add(keys_obj)
            db.session.commit()

            return jsonify({
                "status":"Success",
            })
        
        else:
            return jsonify({
                "status":"Fail"
            })
        
    except Exception as e:
        return str(e.args)

@app.route("/getKey", methods=["GET"])
def getKey():
    try:
        username = request.args.get("username")
        type = request.args.get("type")

        user = Users.query.filter_by(username=username).first()

        if user:
            keys = user.keys
            if type == "public":
                return jsonify({
                    "status":"Success",
                    "key": keys.public_key
                })
            else:
                return jsonify({
                    "status":"Success",
                    "key": keys.private_key
                })
        
        else:
            return jsonify({
                "status":"Fail"
            })
        
    except Exception as e:
        return str(e.args)