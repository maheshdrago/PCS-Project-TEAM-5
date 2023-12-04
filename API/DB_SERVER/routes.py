from DB_SERVER import app, db
from DB_SERVER.models import Users, ChunkMappings, ChunkFileMappings, Permissions, Keys, Directories, DirPermissions
from flask import request, jsonify
import datetime
import logging


logging.basicConfig(filename="app.log", level=logging.DEBUG,
                    format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')


@app.route("/register", methods=['POST'])
def register():
    try:
        data = request.json
        username = data['username']
        password = data['password']

        user = Users(username=username)
        user.set_password(password=password)

        db.session.add(user)
        db.session.commit()
        logging.info("User with Username : {} Registerd Successfully".format(username))
        return "User with Username : {} Registerd Successfully".format(username)
    except Exception as e:
        print(str(e.args))
        return

@app.route("/login", methods=["GET"])
def login():
    username = request.args.get('username')
    password = request.args.get("password")

    user = Users.query.filter_by(username=username).first()


    if user and user.check_password(password):
        logging.info("User with Username : {} logged in Successfully".format(username))
        return "Success"
    else:
        logging.info("User with Username : {} login failed ".format(username))
        return "Fail"



@app.route("/getDirList", methods=["GET"])
def getDirList():

    data = [i.directory_name for i in Directories.query.all()]
    return {
        "data":data
    }

@app.route("/hasDirPermission", methods=["GET"])
def hasDirPermission():
    username = request.args.get("username")
    dirName = request.args.get("dirName")
    permission = request.args.get("permission")

    permissions = DirPermissions.query.filter_by(dir_name=dirName, username=username).first().permissions.split(",")
    if permission in permissions:
        return {
            "status":"Success"
        }
    else:
        return {
            "status":"Fail"
        }

@app.route("/createDir", methods=["GET"])
def createDir():
    name = request.args.get("name")

    db.session.add(Directories(directory_name=name))
    db.session.commit()
    return "Success"
    
    
@app.route("/addChunkMapping", methods=["POST", "PATCH"])
def chunkMapping():
    if request.method == "POST":
        try:
            data = request.json
            pieces = data["pieces"]
            filename = data["filename"]
            has_dir = data["has_dir"]
            
            mapping_objs = []
            
            if has_dir:
                directory = data["directory"]
                dir = Directories.query.filter_by(directory_name=directory).first()
                fileMapping = ChunkFileMappings(filename=filename, directories=dir)
            else:
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

            logging.info("Chunk mappings done for filename: {} ".format(filename))

            return "Success"
        except Exception as e:
            logging.info("Chunk mappings failed for filename: {} at {}".format(filename, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

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
            logging.info("Chunk mappings updated for filename: {} ".format(filename))

            return "Success"
        except Exception as e:
            logging.info("Chunk mappings updation failed for filename: {}".format(filename))

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
            
            logging.info("chunks retrieved for filename: {} ".format(filename))
            return jsonify({
                "status":"success",
                "chunks":pieces
            })
        else:
            logging.info("chunks retrieval failed due to file not found error for filename: {} ".format(filename))
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
            
            logging.info("Chunks deleted for filename: {} ".format(filename))

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
            logging.info("user validation for : {} ".format(username))

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
        
        logging.info("User Permissions {} set for {} for file: {}".format(permission, username, filename))

        return jsonify({
            "status":"Success",
        })
        
    except Exception as e:
        return jsonify({
            "status":str(e.args),
        })

@app.route("/addDirPermissions", methods=["POST"])
def addDirPermissions():
    try:
        data = request.json
        permissions = data['permissions']
        username = data['username']
        dirName = data['dirName']

        permission = DirPermissions(dir_name=dirName, permissions=permissions, username=username)

        db.session.add(permission)
        db.session.commit()
        
        logging.info("User Permissions {} set for {} for dir: {}".format(permission, username,dirName))

        return jsonify({
            "status":"Success",
        })
        
    except Exception as e:
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
        fernet_key = data["fernet_key"]

        user = Users.query.filter_by(username=username).first()

        if user:
            keys_obj = Keys(public_key=public_key, private_key=private_key,fernet_key=fernet_key, user=user)
            db.session.add(keys_obj)
            db.session.commit()
            
            logging.info("Keys added for user : {}".format( username))

            return jsonify({
                "status":"Success",
            })
        
        else:
            return jsonify({
                "status":"Fail"
            })
        
    except Exception as e:
        return str(e.args)

@app.route("/listFiles", methods=["GET"])
def listFiles():
    try:
        files = [i.filename for i in ChunkFileMappings.query.all()]
        return jsonify({
            "status":"Success",
            "files":files
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
            logging.info("Keys accessed of user: {} at {}".format(username, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

            if type == "public":
                return jsonify({
                    "status":"Success",
                    "key": keys.public_key
                })
            elif type=="private":
                return jsonify({
                    "status":"Success",
                    "key": keys.private_key
                })
            else:
                return jsonify({
                    "status":"Success",
                    "key": keys.fernet_key
                })
            
        else:
            logging.warning("Keys accessed of user : {} failed at {}".format(username, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            return jsonify({
                "status":"Fail"
            })
        
        
    except Exception as e:
        return str(e.args)

