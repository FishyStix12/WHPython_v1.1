#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# This script utilizes OpenCV for remote face detection and processing. Upon establishing a 
# connection with a remote host specified by the user, it scans a designated directory for JPEG
# images. Employing a convolutional neural network (CNN)-based face detection model, it
# accurately identifies faces within each image. Extracted faces are then combined into a
# single composite image. Upon completion of processing all images, the composite image is 
# transmitted back to the local host. This script is particularly useful for scenarios 
# requiring distributed face detection tasks across networked devices, ensuring efficient
# and accurate processing of image data.
#################################################################################################
import cv2
import os
import socket
import numpy as np

# Define the directories
ROOT = '/root/Desktop/pictures'  # Source directory containing input images
FACES = '/root/Desktop/faces'    # Directory to save individual detected faces
TRAIN = '/root/Desktop/training' # Directory containing face detection model files


def detect(srcdir=ROOT, tgtdir=FACES, train_dir=TRAIN, target_ip=None, target_port=None):
    # Establish connection with the remote host
    if target_ip and target_port:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((target_ip, target_port))
        except Exception as e:
            print(f"Error connecting to the remote host: {e}")
            return

    # Initialize a list to store all faces
    all_faces = []

    # Loop through each file in the source directory
    for fname in os.listdir(srcdir):
        # Check if the file is a JPG file
        if not fname.upper().endswith('.JPG'):
            continue

        # Get the full path of the source file
        fullname = os.path.join(srcdir, fname)
        # Create the new path for the target file
        newname = os.path.join(tgtdir, fname)

        # Read the image
        img = cv2.imread(fullname)
        if img is None:
            continue

        # Convert the image to grayscale
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # Load the face detection model
        model_path = os.path.join(train_dir, 'opencv_face_detector_uint8.pb')
        config_path = os.path.join(train_dir, 'opencv_face_detector.pbtxt')
        net = cv2.dnn.readNetFromTensorflow(model_path, config_path)

        # Detect faces in the image
        blob = cv2.dnn.blobFromImage(img, 1.0, (300, 300), [104, 117, 123], False, False)
        net.setInput(blob)
        detections = net.forward()

        for i in range(detections.shape[2]):
            confidence = detections[0, 0, i, 2]
            if confidence > 0.5:
                # Get the bounding box coordinates of the face
                box = detections[0, 0, i, 3:7] * np.array([img.shape[1], img.shape[0], img.shape[1], img.shape[0]])
                (startX, startY, endX, endY) = box.astype("int")

                # Extract the face ROI and append to the list
                face = img[startY:endY, startX:endX]
                all_faces.append(face)

    # Close the connection with the remote host
    if target_ip and target_port:
        s.close()

    # Combine all faces into a single image
    final_image = np.zeros((400, 400, 3), dtype=np.uint8)  # Initialize a blank canvas for the final image
    y_offset = 0
    for face in all_faces:
        h, w = face.shape[:2]
        # Check if adding this face would exceed the canvas height
        if y_offset + h > final_image.shape[0]:
            break
        # Paste the face onto the canvas
        final_image[y_offset:y_offset+h, :w] = face
        y_offset += h

    # Save the final image
    final_image_path = os.path.join(tgtdir, 'final_image.jpg')
    cv2.imwrite(final_image_path, final_image)

    # Send the final image back to the local host
    if target_ip and target_port:
        with open(final_image_path, 'rb') as f:
            data = f.read()
        try:
            s.sendall(data)
            print("Final image sent to the local host.")
        except Exception as e:
            print(f"Error sending the final image to the local host: {e}")


if __name__ == '__main__':
    # Input target host IP address and port
    target_ip = input("Enter target host IP address: ")
    target_port = input("Enter target host port: ")
    try:
        target_port = int(target_port)
    except ValueError:
        print("Invalid port number.")
        exit()

    # Run detection
    detect(target_ip=target_ip, target_port=target_port)
