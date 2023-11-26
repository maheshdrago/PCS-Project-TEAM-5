from DB_SERVER import app, db
from DB_SERVER.models import Users, ChunkMappings, ChunkFileMappings
from flask import request, jsonify


@app.route("/register", methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']

    user = Users(username=username, password=password)
    db.session.add(user)
    db.session.commit()

    return "User with Username : {} Registerd Successfully".format(username)

@app.route("/login", methods=["GET"])
def login():
    username = request.args.get('username')
    password = request.args.get("password")

    user = Users.query.filter_by(username=username).first()

    if user and user.password==password:
        return "Success"
    else:
        return "Fail"
    
@app.route("/addChunkMapping", methods=["POST"])
def chunkMapping():
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

@app.route("/retrieveChunks",methods=["GET"])
def retrieveChunks():
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