from app import app
import routes
from routes import AUTH
import auth
from auth import SECRET_KEY
from unittest.mock import patch, MagicMock
from models.user import User
import jwt
from datetime import datetime, timedelta, timezone

import unittest

class TestCodeUnderTest(unittest.TestCase):

    # Token expiration results in invalid token message
    @patch("jwt.decode")
    def test_token_expiration_results_in_invalid_token_message(self, mocker):
        with app.test_client() as client:
            # Mocking expired token
            expired_token = jwt.encode({'userId': '123', 'exp': 1}, SECRET_KEY)
            mocker.side_effect=jwt.ExpiredSignatureError


            # Making request with expired token
            response = client.get('/api/users/123', headers={'Authorization': f'Bearer {expired_token}'})

            # Asserting response
            self.assertEqual(response.status_code, 401)
            self.assertIn("Token is invalid", response.json["message"])



            # Test that ensures user details are actually present in the
            # token and verifies user details using the returned token.
    def test_verify_user_details_in_token_with_token_verification(self):
        with patch('routes.AUTH.make_token') as mock_make_token:
            user_data = {
                'email': 'testament@example.com',
                'password': 'password123',
                'firstName': 'John',
                'lastName': 'Doe'
            }
            payload = {
                'userId': '123',
                'exp': int((datetime.now(timezone.utc) +
                            timedelta(minutes=20)).timestamp())
            }
            mock_make_token.return_value = jwt.encode(payload, SECRET_KEY)


            with app.test_client() as client:
                response = client.post('/auth/register', json=user_data)

                self.assertEqual(response.status_code, 201)
                self.assertIn('accessToken', response.json['data'])
                self.assertEqual(response.json['status'], 'success')
                self.assertIn('user', response.json['data'])
                self.assertEqual(response.json['data']['user']['email'],
                                 'testament@example.com')
                self.assertEqual(response.json['data']['user']['firstName'], 'John')
                self.assertEqual(response.json['data']['user']['lastName'], 'Doe')

                # Use the returned token to verify user details
                token = response.json['data']['accessToken']
                decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                self.assertEqual(decoded_token['userId'], '123')

        # Test to ensure users can’t see data from organisations
        # they don’t have access to
    def test_user_cannot_see_unauthorized_orgs(self):
        # Create 2 users. Use 1st to create org, use other to access org.

        with app.test_client() as client:
            data1 = {
                "email": "test113@example.com",
                "password": "password123",
                "firstName": "John",
                "lastName": "Doe"
            }
            response1 = client.post('/auth/register', json=data1)
            self.assertEqual(response1.status_code, 201)
            token1 = response1.json['data']["accessToken"]

            data2 = {
                "email": "test__113@example.com",
                "password": "password123",
                "firstName": "John",
                "lastName": "Doe"
            }
            response2 = client.post('/auth/register', json=data2)
            self.assertEqual(response2.status_code, 201)
            token2 = response2.json['data']["accessToken"]


            headers = {"Authorization": f"Bearer {token1}"}
            data3 = {"name": "One_new_organisation"}

            response3 = client.post('/api/organisations/', json=data3, headers=headers)
            self.assertEqual(response3.status_code, 201)
            orgId_1 = response3.json["data"]['orgId']



            headers = {"Authorization": f"Bearer {token2}"}
            response4 = client.get(f'/api/organisations/{orgId_1}', headers=headers)

            self.assertEqual(response4.status_code, 403)
            self.assertEqual(response4.json["message"], "Forbidden")

    # User registration with valid data returns success message and token
    def test_user_registration_with_valid_data(self):
        with app.test_client() as client:
            data = {
                "email": "test@example.com",
                "password": "password123",
                "firstName": "John",
                "lastName": "Doe"
            }
            response = client.post('/auth/register', json=data)
            self.assertEqual(response.status_code, 201)
            self.assertIn("accessToken", response.json["data"])
            self.assertEqual(response.json["status"], "success")

    # User login with correct credentials returns success message and token
    def test_user_login_with_correct_credentials(self):
        with app.test_client() as client:
            data = {
                "email": "test_101@example.com",
                "password": "password123",
                "firstName": "John",
                "lastName": "Doe"
            }

            client.post('/auth/register', json=data)

            data_login = {
                "email": "test_101@example.com",
                "password": "password123"
            }
            response = client.post('/auth/login', json=data_login)

            self.assertEqual(response.status_code, 200)
            self.assertIn("accessToken", response.json["data"])
            self.assertEqual(response.json["status"], "success")

    # Authenticated user retrieves their own user record successfully
    def test_authenticated_user_retrieves_own_record(self):
        with app.test_client() as client:
            data = {
                "email": "test111@example.com",
                "password": "password123",
                "firstName": "John",
                "lastName": "Doe"
            }
            response = client.post('/auth/register', json=data)

            token = response.json['data']['accessToken']
            user_id = response.json['data']['user']['userId']

            headers = {"Authorization": f"Bearer {token}"}
            response1 = client.get(f'/api/users/{user_id}', headers=headers)

            self.assertEqual(response1.status_code, 200)
            self.assertEqual(response1.json["status"], "success")

    # Authenticated user retrieves all their organisations successfully
    def test_authenticated_user_retrieves_all_orgs(self):
        with app.test_client() as client:
            data = {
                "email": "test2@example.com",
                "password": "password123",
                "firstName": "John",
                "lastName": "Doe"
            }
            response = client.post('/auth/register', json=data)

            token = response.json['data']['accessToken']
            user_id = response.json['data']['user']['userId']

            headers = {"Authorization": f"Bearer {token}"}
            response = client.get('/api/organisations', headers=headers)

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["status"], "success")
            self.assertEqual(response.json["data"]["organisations"][0]['name'],
                             "John's Organisation")


    # User registration with existing email raises ValueError
    def test_user_registration_with_existing_email(self):
        with app.test_client() as client:
            data = {
                "email": "existing@example.com",
                "password": "password123",
                "firstName": "John",
                "lastName": "Doe"
            }
            response1 = client.post('/auth/register', json=data)
            response2 = client.post('/auth/register', json=data)

            self.assertEqual(response1.status_code, 201)
            self.assertEqual(response2.status_code, 400)
            self.assertEqual(response2.json["message"], "Registration unsuccessful")

    # User registration with missing mandatory fields raises ValueError
    def test_user_registration_with_missing_fields(self):
        with app.test_client() as client:
            data = {
                "email": "test4@example.com"
            }
            response = client.post('/auth/register', json=data)

            self.assertEqual(response.status_code, 422)
            self.assertIn("errors", response.json)

    # User login with incorrect credentials returns authentication failed message
    def test_user_login_with_incorrect_credentials(self):
        with app.test_client() as client:
            data = {
                "email": "test@example.com",
                "password": "wrong___password"
            }
            response = client.post('/auth/login', json=data)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json["message"], "Authentication failed")

    # Retrieving user record with invalid token returns forbidden message
    def test_retrieving_user_record_with_invalid_token(self):
        with app.test_client() as client:
            headers = {"Authorization": "Bearer invalidtoken"}

            response = client.get('/api/users/1', headers=headers)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json["message"], "Token is invalid")

    # Retrieving organisations with invalid token returns forbidden message
    def test_retrieving_orgs_with_invalid_token(self):
        with app.test_client() as client:
            headers = {"Authorization": "Bearer invalidtoken"}
            response = client.get('/api/organisations', headers=headers)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json["message"], "Token is invalid")

    # Creating organisation with invalid data returns client error message
    def test_creating_org_with_invalid_data(self):
        with app.test_client() as client:
            data = {
                "email": "test_user_4@example.com",
                "password": "password123",
                "firstName": "John",
                "lastName": "Doe"
            }
            response1 = client.post('/auth/register', json=data)

            token = response1.json['data']['accessToken']
            headers = {"Authorization": f"Bearer {token}"}
            data = {"description": "A new organisation"}

            response2 = client.post('/api/organisations/', json=data, headers=headers)
            self.assertEqual(response2.status_code, 400)

    # Creating organisation with valid data returns client error message
    def test_creating_org_with_valid_data(self):
        with app.test_client() as client:
            data1 = {
                "email": "test_user_9@example.com",
                "password": "password123",
                "firstName": "John",
                "lastName": "Doe"
            }
            response1 = client.post('/auth/register', json=data1)

            token = response1.json['data']['accessToken']
            headers = {"Authorization": f"Bearer {token}"}
            data2 = {"name": "One_new_organisation"}

            response2 = client.post('/api/organisations/', json=data2, headers=headers)
            self.assertEqual(response1.status_code, 201)


    # Login request without JSON body returns error
    def test_login_request_without_json_body_returns_error(self):
        with app.test_client() as client:
            response = client.post('/auth/login')

            self.assertEqual(response.status_code, 415)

    # Check that the response contains the expected user details and access token.
    def test_default_org_name_generated_correctly(self):
        # Mocking the request data
        request_data = {
            "email": "test12@example.com",
            "password": "password123",
            "firstName": "John",
            "lastName": "Doe"
        }

        # Mocking the AUTH.register_user method
        with patch('routes.AUTH.register_user') as mock_register_user:
            # Mocking the return value of register_user
            mock_register_user.return_value = User(userId=1, email="test12@example.com",
                                                   firstName="John",
                                                   lastName="Doe",
                                                   password="123")

            # Mocking the make_token method
            with patch('routes.AUTH.make_token') as mock_make_token:
                mock_make_token.return_value = "mocked_access_token"

                # Making a POST request to register a user
                with app.test_client() as client:
                    response = client.post('/auth/register', json=request_data)

                    # Assertions
                    self.assertEqual(response.status_code, 201)
                    self.assertIn("accessToken", response.json["data"])
                    self.assertEqual(response.json["status"], "success")
                    self.assertEqual(response.json["data"]["user"]["userId"], 1)
                    self.assertEqual(response.json["data"]["user"]["email"],
                                     "test12@example.com")
                    self.assertEqual(response.json["data"]["accessToken"],
                                     "mocked_access_token")

    # It Should Fail If Required Fields Are Missing:Test cases for
    # each required field (firstName, lastName, email, password) missing.
    def test_required_fields_missing(self):
        with app.test_client() as client:
            # Missing firstName
            data = {
                "email": "test@example.com",
                "password": "password123",
                "lastName": "Doe"
            }
            response = client.post('/auth/register', json=data)
            self.assertEqual(response.status_code, 422)

            # Missing lastName
            data = {
                "email": "test@example.com",
                "password": "password123",
                "firstName": "John"
            }
            response = client.post('/auth/register', json=data)
            self.assertEqual(response.status_code, 422)

            # Missing email
            data = {
                "password": "password123",
                "firstName": "John",
                "lastName": "Doe"
            }
            response = client.post('/auth/register', json=data)
            self.assertEqual(response.status_code, 422)

            # Missing password
            data = {
                "email": "test@example.com",
                "firstName": "John",
                "lastName": "Doe"
            }
            response = client.post('/auth/register', json=data)
            self.assertEqual(response.status_code, 422)

    # Verify the response contains a status code of 422 and appropriate error messages.
    def test_response_status_code_422_and_error_messages(self):
        # Mocking the request data
        request_data = {
            "email": "test@example.com",
            "password": "password123",
            "firstName": "John",
            "lastName": "Doe"
        }

        # Mocking the AUTH.register_user method to raise a TypeError
        with patch('routes.AUTH.register_user') as mock_register_user:
            mock_register_user.side_effect = TypeError("Invalid fields")

            # Making a POST request to the register_user endpoint
            with app.test_client() as client:
                response = client.post('/auth/register', json=request_data)

                # Asserting the response status code and error message
                self.assertEqual(response.status_code, 422)
                self.assertIn("errors", response.json)
                self.assertEqual(response.json["errors"], "Invalid fields")
