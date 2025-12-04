import httpx
import json
import re
from time import sleep
from random import choices, choice
from string import ascii_lowercase, digits, ascii_letters


class Mail:
    def __init__(self) -> None:
        self.generate_url = 'https://api.mail.gw/accounts'
        self.token_url = 'https://api.mail.gw/token'
        self.messages_url = 'https://api.mail.gw/messages'

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': 'application/json',
            'Referer': 'https://mail.gw/',
            'Origin': 'https://mail.gw',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'Connection': 'keep-alive',
            'TE': 'trailers',
        }

        try:
            response = httpx.get('https://api.mail.gw/domains?page=1', headers=self.headers, timeout=10)
            domains_list = [x['domain'] for x in json.loads(response.text)['hydra:member']]
            response.raise_for_status()
            self.domain = choice(domains_list)
        except Exception:
            self.domain = 'maxamba.com'

    def generate_mail(self, proxies: dict = None) -> tuple:
        while True:
            try:
                mail_text = ''.join(choices(ascii_lowercase + digits, k=12))
                mail = f'{mail_text}@{self.domain}'
                password = ''.join(choices(ascii_letters + digits + '$*!', k=12))

                payload = {
                    "address": mail,
                    "password": password
                }

                with httpx.Client(timeout=30) as client:
                    r = client.post(url=self.generate_url, headers=self.headers, json=payload)
                    if r.status_code == 201:
                        auth_response = client.post(url=self.token_url, json=payload)
                        auth_response.raise_for_status()
                        auth_token = auth_response.json()
                        print(f"Generated Email: {mail}")
                        print(f"Generated Password: {password}")
                        return mail, password, auth_token['token']
                    elif r.status_code == 422:
                        print('Generation Error: already used mail address.')
            except Exception as e:
                print(f'Generation Error: {str(e).capitalize()}.')
                sleep(3)

    def get_verification_link(self, token: str, proxies: dict = None) -> str:
        while True:
            try:
                headers = self.headers.copy()
                headers['Authorization'] = f"Bearer {token}"

                with httpx.Client(timeout=30) as client:
                    r = client.get(self.messages_url, headers=headers)
                    r.raise_for_status()
                    messages = r.json()
                    if not messages['hydra:totalItems'] == 0:
                        id = messages['hydra:member'][0]['@id'].split('/')[2]
                        print(id)
                        return id
                    sleep(10)
            except IndexError:
                sleep(1)
            except json.decoder.JSONDecodeError:
                sleep(3)
            except Exception as e:
                print(f'Verification Error: {str(e).capitalize()}.')
                sleep(3)

    def read_mail(self, id: str, token: str) -> str:
        try:
            headers = self.headers.copy()
            headers["Authorization"] = f"Bearer {token}"
            with httpx.Client(timeout=30) as client:
                r = client.get(f"{self.messages_url}/{id}", headers=headers)
                r.raise_for_status()
                return r.json()
        except Exception as e:
            print(f"exception: {e}")

    def delete_mail(self, id: str, token: str) -> None:
        try:
            headers = self.headers.copy()
            headers["Authorization"] = f"Bearer {token}"
            with httpx.Client(timeout=30) as client:
                r = client.delete(f"{self.messages_url}/{id}", headers=headers)
                r.raise_for_status()
                #print(r.text)
                #breakpoint()
        except Exception as e:
            print(f"exception: {e}")


def main():
    mail = Mail()
    email, password, token = mail.generate_mail()
    print(f"Email: {email}, Password: {password}, Token: {token}")
    msg_id = mail.get_verification_link(token)
    mail_text = mail.read_mail(msg_id, token)
    mail.delete_mail(msg_id, token)
    print(mail_text)


if __name__ == "__main__":
    main()
