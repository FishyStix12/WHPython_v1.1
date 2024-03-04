#! /usr/bin/python

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
