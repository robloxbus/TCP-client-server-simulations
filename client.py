import socket
import ssl

HOST = '127.0.0.1'
PORT = 8080
SSL_CERTFILE = 'server_cert.pem'

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=SSL_CERTFILE)
    context.check_hostname = False #disabled for local clients, as with online clients this local host does not work
    context.verify_mode = ssl.CERT_NONE
    secure_client_socket = context.wrap_socket(client_socket, server_hostname=HOST)

    try:
        secure_client_socket.connect((HOST, PORT))

        while True:
            try:
                # Receive server message
                server_message = secure_client_socket.recv(1024).decode('utf-8')
                if not server_message:
                    # Empty response indicates server closed the connection
                    print("[SERVER] Connection closed by the server.")
                    break

                print(f"[SERVER] {server_message}")

                if "Session Summary" in server_message or "Session Timeout Summary" in server_message:
                    print("Exiting session...")
                    break

                if "Question" in server_message:
                    user_answer = input("Your Answer: ").strip().lower()
                    while len(user_answer) <= 0:
                        print("Invalid input. Enter something.\n")
                        user_answer = input("Your Answer: ").strip().lower()
                    secure_client_socket.send(user_answer.encode('utf-8'))
                elif "Please enter your name" in server_message:
                    user_message = input("Please enter your UserID: ").strip()
                    while len(user_message) <= 0:
                        print("Invalid input. Enter something.\n")
                        user_message = input("Please enter your UserID: ").strip().lower()
                    secure_client_socket.send(user_message.encode('utf-8'))
                else:
                    user_message = input("Your Option: ").strip().lower()
                    while len(user_message) != 1 or user_message not in "abcdef":
                        print("Invalid input. Please enter a valid option (a, b, c, d, e, f).")
                        user_message = input("Your Option: ").strip().lower()
                    secure_client_socket.send(user_message.encode('utf-8'))

            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                print("[SERVER] Connection lost. Exiting...")
                break

    except (ConnectionAbortedError, ConnectionResetError):
        print("[ERROR] The connection was forcibly closed.")            
    except ConnectionRefusedError:
        print("Unable to connect to the server. Please check if the server is running.")
    except KeyboardInterrupt:
        print("\nDisconnected from server.")
    finally:
        secure_client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    start_client()
