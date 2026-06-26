import cv2

detector = cv2.QRCodeDetector()


def decode_qr(image_path):
    """
    Decode QR code from an image.
    Returns the decoded text or None.
    """

    image = cv2.imread(image_path)

    if image is None:
        return None

    data, points, _ = detector.detectAndDecode(image)

    if data:
        return data

    return None