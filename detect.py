#! /usr/bin/python
#! /usr/bin/python
#################################################################################################
# Author: Nicholas Fisher
# Date: March 4th 2024
# Description of Script
# The provided Python script uses OpenCV to detect faces in images. It takes a directory containing 
# images as input, detects faces in each image using a pre-trained Haar cascade classifier, 
# highlights the detected faces with rectangles, and saves the modified images in a specified output 
# directory. To use the code, simply run the script, ensuring that the paths to the input images 
# and the Haar cascade classifier are correct. For example, if you have a directory pictures 
# containing images, you can use the following command to detect faces and save the modified 
# images in a directory faces:
# python detect.py
# The output will be modified images with highlighted faces saved in the faces directory. 
# If no faces are detected in an image, a message will be printed indicating that no faces were 
# found in that image.
#################################################################################################

import cv2
import os

# Define the directories
ROOT = '/root/Desktop/pictures'
FACES = '/root/Desktop/faces'
TRAIN = '/root/Desktop/training'


def detect(srcdir=ROOT, tgtdir=FACES, train_dir=TRAIN):
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
        training = os.path.join(train_dir, 'haarcascade_frontalface_alt.xml')
        cascade = cv2.CascadeClassifier(training)
        # Detect faces in the image
        rects = cascade.detectMultiScale(gray, scaleFactor=1.3, minNeighbors=5)

        try:
            # Check if any faces were detected
            if rects.any():
                print('Got a face')
                # Convert the rectangles to (x1, y1, x2, y2) format
                rects[:, 2:] += rects[:, :2]
        except AttributeError:
            print(f'No faces found in {fname}.')
            continue

        # Highlight the faces in the image
        for x1, y1, x2, y2 in rects:
            cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)
        # Save the modified image
        cv2.imwrite(newname, img)


if __name__ == '__main__':
    detect()
