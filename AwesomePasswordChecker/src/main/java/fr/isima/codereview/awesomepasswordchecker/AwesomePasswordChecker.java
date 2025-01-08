package fr.isima.codereview.awesomepasswordchecker;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import java.util.ArrayList;
import java.util.List;


public class AwesomePasswordChecker {

  private static AwesomePasswordChecker instance;

  private final List<double[]> clusterCenters = new ArrayList<>();
  /**
  * Méthode pour créer une instance à partir d'une file donnée.
  * 
  * @param file type File, fichier entré
  * @return instance de la classe
  * @throws IOException si pas d'instance créée (null)
  */
  public static AwesomePasswordChecker getInstance(File file)
  throws IOException {
    if (instance == null) {
      instance = new AwesomePasswordChecker(new FileInputStream(file));
    }
    return instance;
  }
  /**
  * Méthode pour créer une instance avec une file par défaut.
  *
  * @return instance
  * @throws IOException si pas d'instance créée (null)
  */
  public static AwesomePasswordChecker getInstance() throws IOException {
    if (instance == null) {
      InputStream is = new FileInputStream("src/main/java/fr/isima/codereview/awesomepasswordchecker/cluster_centers_HAC_aff.csv");
      instance = new AwesomePasswordChecker(is);

    }
    return instance;
  }
  /**
  * Méthode pour mettre les centres du fichier converti en InputStream dans un tableau clusterCenters.
  * 
  * @param is type InputStream, permet de parcourir des doubles séparés par des virgules issus d'un csv
  * @throws IOException si erreur de lecture de l'InputStreamReader
  */
  private AwesomePasswordChecker(InputStream is) throws IOException {
    BufferedReader br = new BufferedReader(new InputStreamReader(is));
    String line;
    while ((line = br.readLine()) != null) {
      String[] values = line.split(",");
      double[] center = new double[values.length];
      for (int i = 0; i < values.length; ++i) {
        center[i] = Double.parseDouble(values[i]);
      }
      clusterCenters.add(center);
    }
    br.close();
  }
  /**
  * Méthode pour calculer le masque d'un mot de passe.
  * @param password type String
  * @return tableau d'int
  */
  public int[] maskAff(String password) {
    int[] maskArray = new int[28]; 
    int limit = Math.min(password.length(), 28);

    for (int i = 0; i < limit; ++i) {
      char charpswd = password.charAt(i);
      switch (charpswd) {
        case 'e': 
        case 's':
        case 'a':
        case 'i':
        case 't':
        case 'n':
        case 'r':
        case 'u':
        case 'o':
        case 'l':
          maskArray[i] = 1;
          break;
        case 'E':
        case 'S':
        case 'A':
        case 'I':
        case 'T':
        case 'N':
        case 'R':
        case 'U':
        case 'O':
        case 'L':
          maskArray[i] = 3;
          break;
        case '>':
        case '<':
        case '-':
        case '?':
        case '.':
        case '/':
        case '!':
        case '%':
        case '@':
        case '&':
          maskArray[i] = 6;
          break;
        default:
          if (Character.isLowerCase(charpswd)) {
            maskArray[i] = 2;
          } else if (Character.isUpperCase(charpswd)) {
            maskArray[i] = 4;
          } else if (Character.isDigit(charpswd)) {
            maskArray[i] = 5;
          } else {
            maskArray[i] = 7;
          }
      }
    }
    return maskArray;
  }
  /**
  * Méthode pour récupérer une distance entre un mot de passe (sous forme de masque) et un ensemble de centres de clusters.
  * 
  * @param password type String
  * @return double
  */
  public double getDIstance(String password) {
    int[] maskArray = maskAff(password);
    double minDistance = Double.MAX_VALUE;

    //la distance est la plus petite distance euclidienne entre le masque et l'ensemble de centres.

    for (double[] center : clusterCenters) {

      minDistance = Math.min(euclideanDistance(maskArray, center), minDistance);

    }
    return minDistance;
  }
  /**
  * Méthode qui renvoie une distance euclidienne entre deux tableaux.
  * 
  * @param mask type tableau d'entiers
  * @param center type tableau de doubles
  * @return la distance euclidienne
  */
  private double euclideanDistance(int[] mask, double[] center) {
    double sum = 0;
    for (int i = 0; i < Math.min(mask.length, center.length); i++) {
      sum += Math.pow(mask[i] - center[i],2);
    }
    return Math.sqrt(sum);
  }
  /**
  * Méthode pour calculer le hash MD5 d'une chaîne de caractères.
  * 
  * @param input type String
  * @return type String le hash de la string d'entrée
  */
  public static String computeMD5(String input) {
    
    // Step 1: Input transformation

    byte[] inputBytes = input.getBytes();
    int inputLength = inputBytes.length;

    int num512BitBlocks = ((inputLength + 8) >>> 6) + 1;
    int totalPaddedLength = num512BitBlocks << 6;
    byte[] paddingBytes = new byte[totalPaddedLength - inputLength];
    paddingBytes[0] = (byte) 0x80;

    long inputLengthBits = (long) inputLength << 3;
    ByteBuffer lengthBuffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(inputLengthBits);
    byte[] lengthBytes = lengthBuffer.array();

    byte[] paddedinputBytes = new byte[totalPaddedLength];
    System.arraycopy(inputBytes, 0, paddedinputBytes, 0, inputLength);
    System.arraycopy(paddingBytes, 0, paddedinputBytes, inputLength, paddingBytes.length);
    System.arraycopy(lengthBytes, 0, paddedinputBytes, totalPaddedLength - 8, 8);

    // Step 2: Definitions

    int[] md5State = {
      0x67452301,
      0xefcdab89,
      0x98badcfe,
      0x10325476
    };

    int[] md5Constants = {
      0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
      0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
      0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
      0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
      0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
      0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
      0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
      0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    int[] shiftAmounts = {
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    // Step 3: Calculation

    for (int i = 0; i < num512BitBlocks; i++) {
      int[] messageSchedule = new int[16];
      for (int j = 0; j < 16; j++) {
        messageSchedule[j] = ByteBuffer.wrap(paddedinputBytes, (i << 6) + (j << 2), 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
      }

      int first = md5State[0];
      int second = md5State[1];
      int third = md5State[2];
      int fourth = md5State[3];

      for (int j = 0; j < 64; j++) {
        int functionresult;
        int messageIndex;
        if (j < 16) {
          functionresult = (second & third) | (~second & fourth);
          messageIndex = j;
        } else if (j < 32) {
          functionresult = (fourth & second) | (~fourth & third);
          messageIndex = (5 * j + 1) % 16;
        } else if (j < 48) {
          functionresult = second ^ third ^ fourth;
          messageIndex = (3 * j + 5) % 16;
        } else {
          functionresult = third ^ (second | ~fourth);
          messageIndex = (7 * j) % 16;
        }
        final int temp = fourth;
        fourth = third;
        third = second;
        second = second + Integer.rotateLeft(first + functionresult + md5Constants[j] + messageSchedule[messageIndex], shiftAmounts[j]);
        first = temp;
      }

      md5State[0] += first;
      md5State[1] += second;
      md5State[2] += third;
      md5State[3] += fourth;
    }

    // Step 4: Output
    ByteBuffer md5Buffer = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
    md5Buffer.putInt(md5State[0]).putInt(md5State[1]).putInt(md5State[2]).putInt(md5State[3]);
    byte[] md5Bytes = md5Buffer.array();

    StringBuilder md5Hex = new StringBuilder();
    for (byte b : md5Bytes) {
      md5Hex.append(String.format("%02x", b));
    }

    return md5Hex.toString();
  }

  public static void main(String[] args){}
}
