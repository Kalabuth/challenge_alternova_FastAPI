from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from utils.autentication import check_password, generate_access_token
from schema.schema import User
from database.db import get_db
from sqlalchemy.orm import Session 
from models.model import User
from schema.schema import Login as login_schema, User as user_schema
from utils.autentication import hash_password
from datetime import datetime


router = APIRouter(
    prefix="/autentication",
    tags=["Autentication"]
)

@router.post('/login/', response_model=login_schema)
def login(entrada:login_schema, db:Session = Depends(get_db)):
    
    user = db.query(User).filter_by(email=entrada.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    verificaction_password = check_password(entrada.password, user.password)
    
    if not verificaction_password:
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")
    
    token = generate_access_token(user.id)
    
    content = {'success':'True', 'token':token}
    return JSONResponse(content=content, status_code=200)


@router.post('/register/', response_model=user_schema)
def post_user(entrada:user_schema, db:Session = Depends(get_db)):
    
    password = hash_password(entrada.password)
    user = db.query(User).filter_by(email=entrada.email).first()
    if user:
        raise HTTPException(status_code=409, detail="Existe un usuario con el correo ingresado")
    
    user = User(email=entrada.email, password=password, admin=entrada.admin, date_joined=datetime.now())
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
