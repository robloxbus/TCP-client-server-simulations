import socket
import select
import random
from ipaddress import ip_network
import time
import ssl

#Note: CTRL+C to terminate server

HOST = '127.0.0.1' #local host
PORT = 8080 #some port
SSL_CERTFILE = 'server_cert.pem'
SSL_KEYFILE = 'server_key.pem'
CLIENT_TIMEOUT = 180# Client session timeout in 3 minutes, change for testing.

#Generate random questions with random IP addresses
def generate_question(option, base_ip, prefix):
    if option == "a":
        question_text = f"Compute the Network Number for {base_ip}/{prefix}. (Enter format e.g. 192.168.1.1/12)"
        return question_text, (base_ip, prefix)
    elif option == "b":
        question_text = f"Compute the Broadcast Address for {base_ip}/{prefix}. (Enter format e.g. 192.168.1.1)"
        return question_text, (base_ip, prefix)
    elif option == "c":
        question_text = f"Compute the Netmask in DDN for {base_ip}/{prefix}. (Enter format e.g. 255.255.255.0)"
        return question_text, (base_ip, prefix)
    elif option == "d":
        ip1 = f"192.168.1.{random.randint(0, 255)}"
        ip2 = f"192.168.1.{random.randint(0, 255)}"
        prefix = random.randint(8, 30)
        question_text = f"Check if {ip1} and {ip2} belong to the same network with prefix /{prefix}. (Enter true or false.)"
        return question_text, (ip1, ip2, prefix)
    elif option == "e":
        question_text = f"How many total hosts are possible in {base_ip}/{prefix}? (Enter a whole number.)"
        return question_text, (base_ip, prefix)
    return "Invalid option.", None

#solve the questions and compare with user input
def evaluate_answer(option, eval_data, answer):
    try:
        if option == "a":
            base_ip, prefix = eval_data
            network = ip_network(f"{base_ip}/{prefix}", strict=False)
            correct_answer = f"{network.network_address}/{network.prefixlen}"
        elif option == "b":
            base_ip, prefix = eval_data
            network = ip_network(f"{base_ip}/{prefix}", strict=False)
            correct_answer = f"{network.broadcast_address}"
        elif option == "c":
            base_ip, prefix = eval_data
            network = ip_network(f"{base_ip}/{prefix}", strict=False)
            correct_answer = f"{network.netmask}"
        elif option == "d":
            ip1, ip2, prefix = eval_data
            network1 = ip_network(f"{ip1}/{prefix}", strict=False)
            network2 = ip_network(f"{ip2}/{prefix}", strict=False)
            correct_answer = "true" if network1.network_address == network2.network_address else "false"
        elif option == "e":
            base_ip, prefix = eval_data
            network = ip_network(f"{base_ip}/{prefix}", strict=False)
            total_hosts = network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses
            correct_answer = str(total_hosts)
        else:
            return "INVALID", None

        if answer.strip() == correct_answer:
            return "SUCCESS", None
        else:
            return "FAIL", correct_answer
    except ValueError as e:
        return "ERROR", str(e)

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"Server listening on {HOST}:{PORT}")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SSL_CERTFILE, keyfile=SSL_KEYFILE)
    secure_server_socket = context.wrap_socket(server_socket, server_side=True)

    sockets_list = [secure_server_socket]
    clients = {}
    session_data = {}
    last_active = {}

    try:
        while True:
            read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list, 1)
            current_time = time.time()

            for notified_socket in read_sockets:
                if notified_socket == secure_server_socket:
                    try:
                        client_socket, client_address = secure_server_socket.accept()
                        sockets_list.append(client_socket)
                        clients[client_socket] = None
                        session_data[client_socket] = {"correct": 0, "incorrect": 0}
                        last_active[client_socket] = current_time
                        client_socket.send(f"Connected to server: {HOST} Please enter your name.".encode('utf-8'))
                        print(f"Requested identity from {client_address}")
                    except secure_server_socket.timeout:
                        print("Server timed out waiting for connections.")
                        break

                else:
                    try:
                        message = notified_socket.recv(1024).decode('utf-8').strip()
                        if not message:
                            raise ConnectionResetError

                        last_active[notified_socket] = current_time

                        if clients[notified_socket] is None:
                            # Client provides their name
                            clients[notified_socket] = message
                            print(f"Client {message} has connected to the server!")
                            notified_socket.send(f"Welcome, {message}! Select an option:\n"
                                                 "a. Practice computation of Network Number\n"
                                                 "b. Practice computation of Broadcast Address\n"
                                                 "c. Practice computation of Netmask in DDN\n"
                                                 "d. Check if two addresses belong to the same network\n"
                                                 "e. Compute total hosts in a network\n"
                                                 "f. Exit\n".encode('utf-8'))
                        else:
                            # Process client responses
                            if message == "f":
                                summary = session_data[notified_socket]
                                summary_message = (
                                    f"Session Summary:\n"
                                    f"Correct Answers: {summary['correct']}\n"
                                    f"Incorrect Answers: {summary['incorrect']}\nGoodbye!"
                                )
                                notified_socket.send(summary_message.encode('utf-8'))
                                print(f"Client {clients[notified_socket]} closed the connection.")
                                sockets_list.remove(notified_socket)
                                del clients[notified_socket]
                                del session_data[notified_socket]
                                del last_active[notified_socket]
                            elif message in "abcde":
                                # Generate IP and send question
                                base_ip = f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.0"
                                prefix = random.randint(8, 30)
                                question_text, eval_data = generate_question(message, base_ip, prefix)
                                notified_socket.send(f"Question: {question_text}".encode('utf-8'))
                                
                                # Receive answer and evaluate
                                answer = notified_socket.recv(1024).decode('utf-8').strip()
                                last_active[notified_socket] = current_time
                                result, correct_answer = evaluate_answer(message, eval_data, answer)
                                
                                # Provide feedback
                                if result == "SUCCESS":
                                    session_data[notified_socket]["correct"] += 1
                                    notified_socket.send("SUCCESS".encode('utf-8') + "\nSelect an option:\n"
                                                     "a. Practice computation of Network Number\n"
                                                     "b. Practice computation of Broadcast Address\n"
                                                     "c. Practice computation of Netmask in DDN\n"
                                                     "d. Check if two addresses belong to the same network\n"
                                                     "e. Compute total hosts in a network\n"
                                                     "f. Exit\n".encode('utf-8'))
                                elif result == "FAIL":
                                    session_data[notified_socket]["incorrect"] += 1
                                    notified_socket.send(f"FAIL (The correct answer is {correct_answer})".encode('utf-8') + "\nSelect an option:\n"
                                                     "a. Practice computation of Network Number\n"
                                                     "b. Practice computation of Broadcast Address\n"
                                                     "c. Practice computation of Netmask in DDN\n"
                                                     "d. Check if two addresses belong to the same network\n"
                                                     "e. Compute total hosts in a network\n"
                                                     "f. Exit\n".encode('utf-8'))
                                else:
                                    notified_socket.send("INVALID RESPONSE".encode('utf-8'))
                            else:
                                notified_socket.send("Invalid option. Please select a valid option.".encode('utf-8'))
                    except (ConnectionResetError, BrokenPipeError):
                        print(f"Client {clients.get(notified_socket, 'Unknown')} disconnected abruptly.")
                        sockets_list.remove(notified_socket)
                        del clients[notified_socket]
                        del session_data[notified_socket]
                        del last_active[notified_socket]

            # Handle idle clients
            for sock in list(last_active):
                if current_time - last_active[sock] > CLIENT_TIMEOUT:
                    print(f"Client {clients[sock]} timed out.")
                    summary = session_data[sock]
                    summary_message = (
                        f"Session Timeout Summary:\n"
                        f"Correct Answers: {summary['correct']}\n"
                        f"Incorrect Answers: {summary['incorrect']}\nGoodbye!"
                    )
                    try:
                        sock.send(summary_message.encode('utf-8'))
                    except BrokenPipeError:
                        pass
                    sockets_list.remove(sock)
                    del clients[sock]
                    del session_data[sock]
                    del last_active[sock]

            for notified_socket in exception_sockets:
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                del session_data[notified_socket]
                del last_active[notified_socket]
    except KeyboardInterrupt:
        print("\nServer manually terminated.")

    finally:
        print("Shutting down server...")
        for sock in sockets_list:
            sock.close()

if __name__ == "__main__":
    start_server()
