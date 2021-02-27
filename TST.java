import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import static java.lang.Integer.max;
import static java.lang.Integer.min;

/**
 * Class to save different parameters
 */
class TSTNode {

    char data;
    int LO;
    int PO;
    float weight;
    boolean isEnd;
    TSTNode left, middle, right;

    public TSTNode(char data) {
        this.data = data;
        this.isEnd = false;
        this.left = null;
        this.middle = null;
        this.right = null;
    }
}

/**
 * Class that includes all the important functions except tree operations
 */
public class TST {

    public static int feature_size, n_gram_size;
    public static int line_count_legitimate_train, line_count_phishing_train;
    public static int TP = 0, TN = 0, FN = 0, FP = 0, UP = 0, UL = 0;
    public static List<String> l_o = new ArrayList<>(); // List for saving the first 5000 elements of the legitimate features
    public static List<String> p_o = new ArrayList<>(); // List for saving the first 5000 elements of the phishing features

    /**
     * The main function that executes the important bits
     * @throws Exception
     */
    public void execute() throws Exception {
        /* Opening all the necessary output files*/
        FileWriter all_feature_weights = new FileWriter("all_feature_weights.txt");
        FileWriter strong_legitimate_features = new FileWriter("strong_legitimate_features.txt");
        FileWriter strong_phishing_features = new FileWriter("strong_phishing_features.txt");

        n_gram_size = 4; // Setting n-gram size to be used in other functions
        feature_size = 5000; // Setting feature size to be used in other functions

        System.out.println("n-gram based phishing detection via TST\nFeature Size: " + feature_size + "\nn-gram size: " + n_gram_size + "\n");

        fileReader("legitimate-train.txt", "LO","Legitimate"); // Sending file to filereader
        long lineCount_l = Files.lines(Paths.get("legitimate-test.txt")).count(); // Function to get the line count of legitimatetrain file
        System.out.println("Legitimate test file has been loaded with [" + lineCount_l + "] instances");

        fileReader("phishing-train.txt", "PO","Phishing"); // Sending file to filereader
        long lineCount_p = Files.lines(Paths.get("phishing-test.txt")).count(); // Function to get the line count phishingtrain file
        System.out.println("Phishing test file has been loaded with [" + lineCount_p + "] instances");

        System.out.println("TST has been loaded with " + line_count_legitimate_train + " n-grams");
        System.out.println("TST has been loaded with " + line_count_phishing_train + " n-grams");

        TernarySearchTree.traverse(TernarySearchTree.root, ""); // Traversing the tree to do various operations(explained above the actual function)

        TernarySearchTree.phishing_occurence.sort((a, b) -> Integer.compare(Integer.parseInt(b.get(1)), Integer.parseInt(a.get(1)))); // Sorting the phishing list with respect to every element's weights
        TernarySearchTree.legitimate_occurence.sort((a, b) -> Integer.compare(Integer.parseInt(b.get(1)), Integer.parseInt(a.get(1)))); // Sorting the phishing list with respect to every element's weights

        frequency_printer(TernarySearchTree.phishing_occurence, strong_phishing_features, p_o); // Sending to the function to print the occurrences(frequencies) of phishing list
        System.out.println(feature_size + " strong phishing n-grams have been saved to the file \"strong_phishing_features.txt\"");

        frequency_printer(TernarySearchTree.legitimate_occurence, strong_legitimate_features, l_o); // Sending to the function to print the occurrences(frequencies) of legitimate list
        System.out.println(feature_size + " strong legitimate n-grams have been saved to the file \"strong_legitimate_features.txt\"");

        weight_printer(all_feature_weights); // Printing all the n-grams and their weights with a sorted order
        System.out.println(TernarySearchTree.n_gram_count + " n-grams + weights have been saved to the file \"all_feature_weights\"");

        remove_insignificant(TernarySearchTree.legitimate_occurence, p_o); // Removing insignificant n-grams from phishing list
        remove_insignificant(TernarySearchTree.phishing_occurence, l_o); // Removing insignificant n-grams from legitimate list
        System.out.println(TernarySearchTree.deleted_n_gram_count + " insignificant n-grams have been removed from TST");

        test_file_executer("legitimate-test.txt", "Legitimate"); // Doing necessary operations for every url in a legitimatetest file
        test_file_executer("phishing-test.txt", "Phishing"); // Doing necessary operations for every url in a phishingtest file

        System.out.println("TP: " + TP + " FN: " + FN + " TN: " + TN + " FP: " + FP + " Unpredictable Phishing: " + UP + " Unpredictable Legitimate: " + UL );
        float accuracy = (float) (TP + TN) / (TP + TN + FP + FN + UP + UL); // Calculating accuracy
        System.out.println("Accuracy: " + accuracy + "\n");

        /* Closing the files that are created in the beginning of the function */
        all_feature_weights.close();
        strong_legitimate_features.close();
        strong_phishing_features.close();
    }

    /**
     * Function to print the first 5000 elements of the given list as a parameter
     * @param list
     * @param fileWriter
     * @param occurrence
     * @throws IOException
     */
    public static void frequency_printer(List<List<String>> list, FileWriter fileWriter, List<String> occurrence) throws IOException {

        int i = 1;
        for (List<String> node : list) { // Iterating through the list of List<String> which each element having the n-gram as the first element and the weight of it as the second element

            fileWriter.write(i + ". " + node.get(0) + " - freq: " + node.get(1) + "\n");
            occurrence.add(node.get(0)); // Adding to the list
            i++;
            if (i == feature_size + 1) break;

        }
    }

    /**
     * Function to remove the insignificant n-grams from the ternary search tree
     * @param list
     * @param checklist
     */
    public static void remove_insignificant(List<List<String>> list, List<String> checklist) {

        for (int i = feature_size + 1; i < list.size(); i++) {
            if (!checklist.contains(list.get(i).get(0))) { // Checking the list if the n-gram is in the first 5000 elements, otherwise sends in to the delete function
                TernarySearchTree.delete(TernarySearchTree.root, list.get(i).get(0).toCharArray(), 0);
            }
        }
    }

    /**
     * Function to read the train files and sending each line with divided n-grams to the ternary search tree for insertion
     * @param filename
     * @param identifier
     * @param filename_output
     * @throws IOException
     */
    public static void fileReader(String filename, String identifier, String filename_output) throws IOException {

        int line_count = 0;
        BufferedReader br = new BufferedReader(new FileReader(new File(filename)));
        String line;

        /* Extracting 'https', 'http', 'www' and dividing to n-grams and sending it to the insert function*/
        while ((line = br.readLine()) != null) {
            line = line.replaceAll("https", "").replaceAll("http", "").replaceAll("www", "").toLowerCase();
            for (int i = 0; i < line.length() - n_gram_size + 1; i++) {
                TernarySearchTree.insert(line.substring(i, i + n_gram_size), identifier);
            }
            line_count++;
        }

        if (filename_output.equals("Legitimate")) line_count_legitimate_train = line_count; // Setting the line count of the legitimate-train.txt
        if (filename_output.equals("Phishing")) line_count_phishing_train = line_count; // Setting the line count of the legitimate-train.txt

        System.out.println(filename_output + " training file has been loaded with [" + line_count + "] instances");

    }

    /**
     * Function to read the test text files and checking if it's n-grams are present in the tst
     * if so adding it to the line's weight to be summed and determining according to the file type
     * @param filename
     * @param filename_output
     * @throws IOException
     */
    public static void test_file_executer(String filename, String filename_output) throws IOException {

        BufferedReader br = new BufferedReader(new FileReader(new File(filename)));
        String line;
        float weight, temp;

        /* Extracting 'https', 'http', 'www' and dividing to n-grams and summing up the weights of the n-grams if present in the tst*/
        while ((line = br.readLine()) != null) {

            weight = 0;
            line = line.replaceAll("https", "").replaceAll("http", "").replaceAll("www", "").toLowerCase();

            for (int i = 0; i < line.length() - n_gram_size + 1; i++) {

                temp = TernarySearchTree.search(TernarySearchTree.root, line.substring(i, i + n_gram_size).toCharArray(), 0);
                if (temp >= -1 && temp <= 1) {
                    weight += temp;
                }

            }

            /* If the file is legitimate-test file*/
            if (filename_output.equals("Legitimate")) {

                if (weight > 0) FN++; // Incrementing if it is denoted legitimate but turned out to be phishing
                else if (weight < 0) TN++; // Incrementing if it is denoted legitimate and turned out to be legitimate
                else UL++; // If the summation of the weights are 0 increment unpredictable legitimate

            }
            /* If the file is phishing-test file*/
            else if (filename_output.equals("Phishing")) {

                if (weight > 0) TP++; // Incrementing if it is denoted phishing and turned out to be phishing
                else if (weight < 0) FP++; // Incrementing if it is denoted phishing but turned out to be legitimate
                else UP++; // If the summation of the weights are 0 increment unpredictable phishing

            }
        }
    }

    /**
     * Sorting the list of all n-grams and printing them with their weights
     * @param weight
     * @throws Exception
     */
    public static void weight_printer(FileWriter weight) throws Exception {

        weight.write("All N-Gram Weights\n");
        TernarySearchTree.n_grams.sort((a, b) -> Float.compare(Float.parseFloat(b.get(1)), Float.parseFloat(a.get(1))));

        for (List<String> sorted_version_ngram : TernarySearchTree.n_grams) {
            weight.write(sorted_version_ngram.get(0) + " - weight: " + sorted_version_ngram.get(1) + "\n");
        }

    }
}

/**
 * Class that includes the functions for tree operations
 */
class TernarySearchTree {

    public static TSTNode root;
    public static List<List<String>> n_grams = new ArrayList<>(); // List for keeping all the n-grams and their weights
    public static List<List<String>> legitimate_occurence = new ArrayList<>(); // List for legitimate n-grams
    public static List<List<String>> phishing_occurence = new ArrayList<>(); // List for phishing n-grams
    public static int n_gram_count = 0, deleted_n_gram_count = 0;

    public TernarySearchTree() {
        root = null;
    }

    /**
     * Function for inserting the TST
     * @param word
     * @param occurence
     */
    public static void insert(String word, String occurence) {
        root = insert(root, word.toCharArray(), 0, occurence);
    }

    /**
     * Function to insert an n-gram to the TST
     * @param r
     * @param word
     * @param ptr
     * @param occurence
     * @return
     */
    public static TSTNode insert(TSTNode r, char[] word, int ptr, String occurence) {

        if (r == null) r = new TSTNode(word[ptr]); // Create if the node is null

        if (word[ptr] < r.data) r.left = insert(r.left, word, ptr, occurence); // Go left if the value is lesser

        else if (word[ptr] > r.data) r.right = insert(r.right, word, ptr, occurence); // Go right if the value is greater

        else {
            if (ptr + 1 < word.length) r.middle = insert(r.middle, word, ptr + 1, occurence); // Go down if the same

            else {
                /* Check if the n-gram is coming from the legitimate-train.txt*/
                if (occurence.equals("LO")) {
                    if (r.LO > 0) r.LO++; // If already exists increment it's occurrence
                    else r.LO = 1;
                }

                /* Check if the n-gram is coming from the phishing-train.txt*/
                if (occurence.equals("PO")) {
                    if (r.PO > 0) r.PO++; // If already exists increment it's occurrence
                    else r.PO = 1;
                }

                r.isEnd = true; // Set true to indicate that it is the end of the word
            }
        }
        return r;
    }

    /**
     * Function to delete the n-gram from TST
     * @param r
     * @param word
     * @param ptr
     */
    public static void delete(TSTNode r, char[] word, int ptr) {

        if (r == null) return;

        if (word[ptr] < r.data) delete(r.left, word, ptr);

        else if (word[ptr] > r.data) delete(r.right, word, ptr);

        else {

            /* If it is the n-gram wanted to be deleted */
            if (r.isEnd && ptr == word.length - 1) {

                r.isEnd = false; // Set false to lose it in the TST
                deleted_n_gram_count++; // Increment the deleted n-gram count to use is later

            } else if (ptr + 1 < word.length) delete(r.middle, word, ptr + 1);
        }
    }

    /**
     * Function to traverse the TST and calculate all the n-grams' weights and add the n-grams to the related lists
     * @param r
     * @param str
     */
    public static void traverse(TSTNode r, String str) {

        if (r != null) {

            traverse(r.left, str);
            str = str + r.data;

            /* Check if the n-gram is a word*/
            if (r.isEnd) {

                List<String> temp = new ArrayList<>();
                n_gram_count++; // Increment the n-gram to print it later
                temp.add(str);
                temp.add(String.valueOf(weight_calculator(r.PO, r.LO))); // Add the weight of the n-gram to the list
                n_grams.add(temp);
                r.weight = weight_calculator(r.PO, r.LO); // Set the weight of the n-gram

                /* Check if the n-gram is just present in phishing-train.txt*/
                if (r.weight == 1) {

                    List<String> temp2 = new ArrayList<>();
                    temp2.add(str);
                    temp2.add(String.valueOf(r.PO));
                    phishing_occurence.add(temp2);

                }
                /* Check if the n-gram is just present in legitimate-train.txt */
                else if (r.weight == -1) {

                    List<String> temp3 = new ArrayList<>();
                    temp3.add(str);
                    temp3.add(String.valueOf(r.LO));
                    legitimate_occurence.add(temp3);

                }
                /* Check if the n-gram is present in both phishing-train.txt and legitimate-train.txt */
                else {

                    List<String> temp4_phishing = new ArrayList<>();
                    List<String> temp5_legitimate = new ArrayList<>();
                    temp4_phishing.add(str);
                    temp4_phishing.add(String.valueOf(r.PO));
                    phishing_occurence.add(temp4_phishing);
                    temp5_legitimate.add(str);
                    temp5_legitimate.add(String.valueOf(r.LO));
                    legitimate_occurence.add(temp5_legitimate);

                }
            }

            traverse(r.middle, str);
            str = str.substring(0, str.length() - 1);
            traverse(r.right, str);

        }
    }

    /**
     * Function to search an n-gram in the TST
     * @param r
     * @param word
     * @param ptr
     * @return
     */
    public static float search(TSTNode r, char[] word, int ptr) {

        if (r == null) return -13;

        if (word[ptr] < r.data) return search(r.left, word, ptr);

        else if (word[ptr] > r.data) return search(r.right, word, ptr);

        else {

            if (r.isEnd && ptr == word.length - 1) return r.weight; // If the n-gram found return it's weight to use with test files
            else if (ptr == word.length - 1) return -13;
            else return search(r.middle, word, ptr + 1);

        }
    }

    /**
     * Function to calculate the n-gram's weight according to it's occurrence
     * @param PO --> Phishing occurrence
     * @param LO --> Legitimate occurrence
     * @return
     */
    public static float weight_calculator(int PO, int LO) {

        if (PO > 0 && LO == 0) return 1; // If just present in phishing return 1 that denotes it is phishing

        else if (PO == 0 && LO > 0) return -1; // If just present in legitimate return 1 that denotes it is legitimate

        else if (PO > 0 && LO > 0) { // If present in both do the related operations

            if (PO > LO) return ((float) min(PO, LO) / (float) max(PO, LO));

            else if (PO < LO) return ((float) -min(PO, LO) / (float) max(PO, LO));

            else return 0;

        } else {

            return -17;

        }
    }
}