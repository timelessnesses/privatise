import requests
import unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
import io

url = "https://privatise-cf.timelessnesses.workers.dev/"

class TestCase(unittest.TestCase):
	def test_upload(self):
		with open('test.png', 'rb') as f:
			nonce = os.urandom(12)
			key = AESGCM.generate_key(256)
			cipher = AESGCM(key)
			encrypted_file = cipher.encrypt(nonce, f.read(), None)
			r = requests.post(url + "upload", data={
				'expires_at': 1000,
				'file_ext': 'png',
				'name': 'test.png',
			}, files={'file': encrypted_file})
			print(r.text)
			self.assertEqual(r.status_code, 200)
			self.assertIn('id', r.json())
			self.assertIn('expires_at', r.json())

	def test_upload_encrypt_serverside(self):
		with open('test.png', 'rb') as f:
			r = requests.post(url + "upload_encrypt_serverside", data={
				'expires_at': 1000,
				'file_ext': 'png',
				'name': 'test.png',
			}, files={
				'file': f
			})
			print(r.text)
			self.assertEqual(r.status_code, 200)

	def test_read(self):
		with open('test.png', 'rb') as f:
			r = requests.post(url + "upload_encrypt_serverside", data={
				'name': 'test.png',
				'expires_at': 1000,
				'file_ext': 'png',
			}, files={
				'file': f
			})

			encryption_info = r.json()
			self.assertEqual(r.status_code, 200)
			r = requests.get(url + "read", params={
				'file_name': encryption_info['id'],
			}, stream=True)
			self.assertEqual(r.status_code, 200)
			thingy = io.BytesIO()
			for chunk in r.iter_content(chunk_size=8192):
				thingy.write(chunk)
			nonce = base64.b64decode(encryption_info["encryption_info"]["nonce"])
			key = base64.b64decode(encryption_info["encryption_info"]["key"])
			cipher = AESGCM(key)
			thingy.seek(0)
			decrypted_file = cipher.decrypt(nonce, thingy.read(), None)
			f.seek(0)
			self.assertEqual(decrypted_file, f.read())

	def test_read_encrypt_serverside(self):
		with open('test.png', 'rb') as f:
			r = requests.post(url + "upload_encrypt_serverside", data={
				'name': 'test.png',
				'expires_at': 1000,
				'file_ext': 'png',
			}, files={
				'file': f
			})
			encryption_info = r.json()
			print(encryption_info, "stuff")
			self.assertEqual(r.status_code, 200)
			r = requests.get(url + "read_serverside", params={
				'file_name': encryption_info['id'],
				'key': encryption_info["encryption_info"]["key"],
				'nonce': encryption_info["encryption_info"]["nonce"],
			}, stream=True)
			# print(r.text)
			self.assertEqual(r.status_code, 200)
			thingy = io.BytesIO()
			for chunk in r.iter_content(chunk_size=8192):
				thingy.write(chunk)
			thingy.seek(0)
			f.seek(0)
			self.assertEqual(thingy.read(), f.read())
	def test_info(self):
		with open('test.png', 'rb') as f:
			r = requests.post(url + "upload_encrypt_serverside", data={
				'name': 'test.png',
				'expires_at': 1000,
				'file_ext': 'png',
			}, files={
				'file': f
			})
			encryption_info = r.json()
			self.assertEqual(r.status_code, 200)
			r = requests.get(url + "info", params={
				'file_name': encryption_info['id'],
			})
			self.assertEqual(r.status_code, 200)
			info = r.json()
			print()
			self.assertEqual(info['id'], encryption_info['id'])
			self.assertEqual(info['expires_at'], encryption_info['expires_at'])
			self.assertEqual(info['original_file_extension'], "png")
			print(info)

	def test_delete(self):
		with open('test.png', 'rb') as f:
			r = requests.post(url + "upload_encrypt_serverside", data={
				'name': 'test.png',
				'expires_at': 1000,
				'file_ext': 'png',
			}, files={
				'file': f
			})
			encryption_info = r.json()
			self.assertEqual(r.status_code, 200)
			r = requests.delete(url + "delete", params={
				'file_name': encryption_info['id'],
				'key': encryption_info["encryption_info"]["key"],
				'nonce': encryption_info["encryption_info"]["nonce"],
			})
			self.assertEqual(r.status_code, 200)
			r = requests.get(url + "info", params={
				'file_name': encryption_info['id'],
			})
			self.assertEqual(r.status_code, 404)


if __name__ == '__main__':
	unittest.main()
