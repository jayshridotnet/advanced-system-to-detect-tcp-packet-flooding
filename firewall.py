import pandas as pd
import numpy as np
import tkinter as tk
from tkinter import filedialog
import subprocess
import pyshark
import csv
import time
import datetime

# All the Keras required Functions

from keras.models import Sequential
from keras.layers import Dense, Dropout, Flatten, Conv1D, Conv2D, MaxPooling1D
from keras.optimizers import Adam
from keras.utils import to_categorical
from keras import regularizers
from keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, Dropout, GlobalMaxPooling2D
from keras.optimizers import Adam

# All the scikit-learn required Functions

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split

def CNN_Train_Model():
    
    global model, X_train, y_train, X_test, y_test
    df = pd.read_csv('packet_capture.csv')

    # Drop any rows with null values
    df.dropna(inplace=True)

    # To avoid any unwanted spaces in header
    df.columns = [col.strip() for col in df.columns]

    # Important Coloumns
    df = df[['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']]

    # Label Encoder
    df['Label'] = df['Label'].map({'BENIGN': 0, 'DDoS': 1})

    # Forming new preprocessed Dataset
    df.to_csv('preprocessed_ddos.csv', index=False)

    df = pd.read_csv("preprocessed_ddos.csv")

    # Check for NaN and infinity values
    print(np.isnan(df).sum()) # 0 
    print(np.isinf(df).sum()) # 60

    # Replace infinity values with a large number
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(1e9, inplace=True)

    # Normalize the input data (For better accuracy, shoudnt have any other datatypes. Thus did the above steps)
    scaler = MinMaxScaler() # give values in range of 0 to 1
    X = scaler.fit_transform(df.iloc[:, :-1].values)

    # Split the data into training and testing sets
    y = to_categorical(df.iloc[:, -1].values)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1, 1)
    X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1, 1)

    # CNN model
    model = Sequential()
    model.add(Conv2D(32, kernel_size=(3,3), activation='relu', input_shape=(X_train.shape[1], 1, X_train.shape[2]), strides=(1,1), padding='same'))
    model.add(MaxPooling2D(pool_size=(2,2), strides=(2,2), padding='same'))
    model.add(Dropout(0.25))
    model.add(Conv2D(64, kernel_size=(3,3), activation='relu', strides=(1,1), padding='same'))
    model.add(MaxPooling2D(pool_size=(2,2), strides=(2,2), padding='same'))
    model.add(Dropout(0.25))
    model.add(GlobalMaxPooling2D())
    model.add(Dense(128, activation='relu'))
    model.add(Dropout(0.5))
    model.add(Dense(64, activation='relu'))
    model.add(Dense(2, activation='softmax', kernel_regularizer=regularizers.l2(0.01)))

    # Model Compilation
    model.compile(loss='categorical_crossentropy', optimizer=Adam(lr=0.001), metrics=['accuracy'])

    # Fit the model to the training data
    model.fit(X_train, y_train, batch_size=128, epochs=9)

    # Testing data
    loss, accuracy = model.evaluate(X_test, y_test, verbose=1)
    #print("Test accuracy:", accuracy)

def packet_capture():
    
    capture = pyshark.LiveCapture(interface='WiFi')

    # Open the CSV file for writing
    with open('captured_packets.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write the header row
        writer.writerow(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length'])
        # Start the capture and record the start time
        capture.sniff(timeout=10)
        print("Packet Capturing Lenght")
        print(len(capture))
        start_time = time.time() ####

        # Capture packets and write them to the CSV file
        for i, packet in enumerate(capture):
            try:
                source = packet.ip.src
                destination = packet.ip.dst
            except AttributeError:
                # Ignore non-IP packets
                continue

            # Calculate the elapsed time since the start of the capture
            elapsed_time = time.time() - start_time 
            #elapsed_time_ms = int((packet.sniff_time - start_time) * 1000)

            writer.writerow([i, elapsed_time * 0.1 , source, destination, packet.transport_layer, packet.length])

            if elapsed_time * 0.1 >= 10 and i >= 100:
                break

def Run_CNN():
    
    model.fit(X_train, y_train, batch_size=128, epochs=9)
    loss, accuracy = model.evaluate(X_test, y_test, verbose=1)

    return loss, accuracy

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("Firewall") # set the title of the main window
        self.grid()
        self.create_widgets()

    def create_widgets(self):

        # Capturing and Run Firewall Button
        self.run_capture_firewall_button = tk.Button(self)
        self.run_capture_firewall_button["text"] = "Capture & Run Firewall"
        self.run_capture_firewall_button["command"] = self.run_capture_firewall
        self.run_capture_firewall_button.grid(row=0, column=0)

        # Create the Run Firewall button
        self.run_firewall_button = tk.Button(self)
        self.run_firewall_button["text"] = "Run Firewall Manually"
        self.run_firewall_button["command"] = self.run_firewall
        self.run_firewall_button.grid(row=0, column=1)

        # Create the Display Details button
        self.display_details_button = tk.Button(self)
        self.display_details_button["text"] = "Display Details"
        self.display_details_button["command"] = self.display_details
        self.display_details_button.grid(row=0, column=2)

        # Create the text area to display the results
        self.result_text = tk.Text(self)
        self.result_text.grid(row=1, column=0, columnspan=3)
        
        '''# Set the size of the window based on the size of the result_text widget
        self.master.update_idletasks()
        width = self.result_text.winfo_reqwidth()
        height = self.result_text.winfo_reqheight()
        self.master.geometry(f"{width}x{height}")'''

        # Create the file selection button and entry
        self.file_label = tk.Label(self, text="Enter CSV file name:")
        self.file_label.grid(row=2, column=0)
        self.file_entry = tk.Entry(self)
        self.file_entry.grid(row=2, column=1)
        self.file_select_button = tk.Button(self, text="Select File", command=self.select_file)
        self.file_select_button.grid(row=2, column=3)

    def select_file(self):
        # Open a file dialog to select the CSV file
        filename = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, filename)

    def run_capture_firewall(self):
        
        packet_capture()
        
        global df, tcp_df, udp_df , arp_df , other_df , packet_counts, time_frame_size
        
        self.result_text.delete('1.0', tk.END)
        filename = "captured_packets.csv"

        df = pd.read_csv(filename, encoding='latin-1')

        flag = 0 

        # Filtering all the packets.
        tcp_df = df[df['Protocol'].isin(['TCP', 'TLSv1.2'])]
        udp_df = df[df['Protocol'].isin(['UDP', 'DNS', 'MDNS', 'QUIC', 'SSDP'])]
        arp_df = df[df['Protocol'] == 'ARP']
        other_df = df[~df['Protocol'].isin(['TCP', 'TLSv1.2', 'UDP', 'DNS', 'MDNS', 'QUIC', 'SSDP', 'ARP'])]

        df['Time'] = pd.to_datetime(df['Time'])

        time_frame_size = 0.001 # This is going to be very small value. In milliseconds
        # Starting and Ending time for each time frame is calculated here. 
        start_times = pd.date_range(start=df['Time'].iloc[0], end=df['Time'].iloc[-1], freq=f"{time_frame_size}us")
        end_times = start_times + pd.Timedelta(milliseconds=time_frame_size)

        # Store the packet count for each time frame
        packet_counts = {}

        # Iterate through it
        
        for i in range(len(start_times)):
            mask = (df['Time'] >= start_times[i]) & (df['Time'] < end_times[i])
            count = df.loc[mask].shape[0]
            packet_counts[f"{start_times[i]} to {end_times[i]} seconds"] = count
        
        for time_frame, packet_count in packet_counts.items():
            if (packet_count >= 5000):
                flag = 1

        if (flag == 1):
             self.result_text.tag_config("blink", foreground="red")
             self.result_text.tag_raise("blink")
             # Insert the text with the "blink" tag
             self.result_text.insert(tk.END, "DDOS DETECTED!!!\n\n\n", "blink")
        else:    
            self.result_text.insert(tk.END, f"DDOS NOT DETECTED\n\n\n")

    def run_firewall(self):
        
        self.result_text.delete('1.0', tk.END)

        # Reading the CSV File
        global df, tcp_df, udp_df , arp_df , other_df , packet_counts, time_frame_size
        
        filename = self.file_entry.get()
        if filename == "":
            self.result_text.insert(tk.END, "Please select a file first\n")
            return
        try:
            df = pd.read_csv(filename, encoding='latin-1')
        except Exception as e:
            self.result_text.insert(tk.END, f"Error reading file: {str(e)}\n")
            return

        flag = 0 

        # Filtering all the packets.
        tcp_df = df[df['Protocol'].isin(['TCP', 'TLSv1.2'])]
        udp_df = df[df['Protocol'].isin(['UDP', 'DNS', 'MDNS', 'QUIC', 'SSDP'])]
        arp_df = df[df['Protocol'] == 'ARP']
        other_df = df[~df['Protocol'].isin(['TCP', 'TLSv1.2', 'UDP', 'DNS', 'MDNS', 'QUIC', 'SSDP', 'ARP'])]

        df['Time'] = pd.to_datetime(df['Time'])

        time_frame_size = 0.001 # This is going to be very small value. In milliseconds
        # Starting and Ending time for each time frame is calculated here. 
        start_times = pd.date_range(start=df['Time'].iloc[0], end=df['Time'].iloc[-1], freq=f"{time_frame_size}us")
        end_times = start_times + pd.Timedelta(milliseconds=time_frame_size)

        # Store the packet count for each time frame
        packet_counts = {}

# Iterate through it
        for i in range(len(start_times)):
            mask = (df['Time'] >= start_times[i]) & (df['Time'] < end_times[i])
            count = df.loc[mask].shape[0]
            packet_counts[f"{start_times[i]} to {end_times[i]} seconds"] = count

            # if the packet count exceeds 10000/5000***************************, then flag is set to 1 and loop is broken
        
        for time_frame, packet_count in packet_counts.items():
            if (packet_count >= 5000):
                flag = 1

        if (flag == 1):
             self.result_text.tag_config("blink", foreground="red")
             self.result_text.tag_raise("blink")
             # Insert the text with the "blink" tag
             self.result_text.insert(tk.END, "DDOS DETECTED!!!\n\n\n", "blink")
        else:    
            self.result_text.insert(tk.END, f"DDOS NOT DETECTED\n\n\n")

    def display_details(self):
        
        self.result_text.delete('3.0', tk.END)
        # Printing total number of packets
        self.result_text.insert(tk.END, f'Total number of packets: {len(df)}\n\n')

        # Printing number of TCP, UDP, ARP and other packets
        self.result_text.insert(tk.END, f'Number of TCP packets: {len(tcp_df)}\n')
        self.result_text.insert(tk.END, f'Number of UDP packets: {len(udp_df)}\n')
        self.result_text.insert(tk.END, f'Number of ARP packets: {len(arp_df)}\n')
        self.result_text.insert(tk.END, f'Number of other packets: {len(other_df)}\n\n')

         # Printing other important data
        self.result_text.insert(tk.END, f'Top 5 source addresses for TCP packets:\n{tcp_df["Source"].value_counts().head()}\n\n')
        self.result_text.insert(tk.END, f'Top 5 destination addresses for TCP packets:\n{tcp_df["Destination"].value_counts().head()}\n\n')
        self.result_text.insert(tk.END, f'Maximum packet length for TCP packets: {tcp_df["Length"].max()} bytes\n\n')
        
        for time_frame, packet_count in packet_counts.items():
            #print(f"{time_frame} -> {packet_count} packets")
            self.result_text.insert(tk.END, f'{time_frame} -> {packet_count} packets\n\n')

root = tk.Tk()
app = Application(master=root)
app.mainloop()