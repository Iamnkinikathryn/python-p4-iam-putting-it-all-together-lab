from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


# Resource for user signup
class Signup(Resource):
    def post(self):
        data = request.json
        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        if not username or not password:
            return {"message": "Username and password are required"}, 400

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {"message": "Username already exists"}, 400

        # Create new user
        new_user = User(
            username=username, password_hash=password, image_url=image_url, bio=bio
        )

        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return {"message": "Error creating user"}, 500

        return {"message": "User created successfully"}, 201


# Resource to check current session
class CheckSession(Resource):
    def get(self):
        if "user_id" in session:
            user_id = session["user_id"]
            user = User.query.get(user_id)
            if user:
                return {"username": user.username}, 200
        return {"message": "Unauthorized"}, 401


# Resource for user login
class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"message": "Username and password are required"}, 400

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return {"message": "Login successful"}, 200
        else:
            return {"message": "Invalid credentials"}, 401


# Resource for user logout
class Logout(Resource):
    def get(self):
        if "user_id" in session:
            session.pop("user_id")
            return {"message": "Logged out successfully"}, 200
        else:
            return {"message": "Unauthorized"}, 401


# Resource for fetching all recipes
class RecipeIndex(Resource):
    def get(self):
        if "user_id" not in session:
            return {"message": "Unauthorized"}, 401

        user_id = session["user_id"]
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found"}, 404

        recipes = user.recipes
        serialized_recipes = [recipe.to_dict() for recipe in recipes]
        return {"recipes": serialized_recipes}, 200


# Add resources to API with endpoints
api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")

# Run Flask app
if __name__ == "__main__":
    app.run(port=5555, debug=True)
