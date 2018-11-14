package mil.nga.pki.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import javax.xml.bind.DatatypeConverter;

import mil.nga.pki.tools.Options;
import mil.nga.pki.tools.Options.Multiplicity;
import mil.nga.pki.tools.Options.Separator;

/**
 * This application will read a trust store file in JKS format and export all 
 * of the public keys.  The output will be either a single concatenated 
 * PEM-formatted file, or as individual files named by their alias.
 *  
 * @author L. Craig Carpenter
 */
public class ExportJKSFile {

    /**
     * Usage String printed when incorrect arguments are supplied.
     */
    private static final String USAGE_STRING = 
        new String("Usage: java mil.nga.pki.tools.ExportJKSFile " 
                + "-keystore=<path-to-key-store> "
                + "-output=<path-to-output-file> " 
                + "[ -singleFile ] "
                + "[-h] [-help]" );
    
    /**
     * Help string printed when -h or -help appear on the command line.
     */
    private static final String HELP_STRING = new String(
            "This application will read the keystore file (in JKS format) and "
            + "export all of the public keys in PEM format (i.e. base64) to "
            + "the output file specified.\n\n"
            + "-keystore=<path-to-key-store> The full path to the target JKS "
            + "file to read/parse.\n" 
            + "-output=<path-to-output-file> The full path to the output "
            + "file that will contain the list of PEM-formatted "
            + "certificates.\n" 
            + "[ -singleFile ] If this parameter is set, the certificates "
            + "will be written into a single concatentated PEM-formatted "
            + "file.\n");
    
    /**
     * Used to output the command line arguments for debugging purposes
     */
    private static boolean DEBUG = true;
    
    /**
     * Sets the length of any line for output.
     */
    private static final int PEM_LINE_LENGTH = 64;
    
    /**
     * Extension to append to the output filenames.
     */
    private static final String PEM_FILE_EXTENSION = ".pem";
    
    /**
     * System-dependent new-line character.
     */
    private static final String NEW_LINE = System.getProperty("line.separator");
    
    /**
     * Default constructor.
     */
    public ExportJKSFile() { }
    
    /** 
     * The extracted PEM certificate will be converted to a base64 String
     * and then split up into an array of strings, each line no longer than
     * a constant length (currently 64).
     * 
     * @param cert The X509 certificate to export.
     * @return An array of Strings representing the input X509 certificate.
     * @throws CertificateEncodingException Thrown if the incoming certificate
     * cannot be encoded as base64.
     */
    private List<String> split (X509Certificate cert) 
            throws CertificateEncodingException {
        
        List<String> split = new ArrayList<String>();
        if (cert != null) {
            
            String pemCert = DatatypeConverter.printBase64Binary(
                    cert.getEncoded());
            for (int start = 0; 
                    start < pemCert.length(); 
                    start += PEM_LINE_LENGTH) {
                split.add(
                        pemCert.substring(start, 
                                Math.min(pemCert.length(), start + PEM_LINE_LENGTH)));
            }
        }
        return split;
    }
    
    /**
     * Simple method used to convert the input certificate to a String and 
     * write it to the input <code>BufferedWriter</code> object.
     * 
     * @param cert A <code>X509Certificate</code> object.
     * @param writer The previously constructed <code>BufferedWriter</code>.
     * object.
     * @throws CertificateEncodingException Thrown if the certificate cannot 
     * be base64 encoded.
     * @throws IOException Thrown if there are errors writing to the target 
     * <code>BufferedWriter</code> object.
     */
    public void writeCertificate(
            X509Certificate cert,
            BufferedWriter  writer) 
                    throws CertificateEncodingException, IOException {
        
        if (cert != null) {
            if (writer != null) {
                writer.write("-----BEGIN CERTIFICATE-----");
                writer.write(NEW_LINE);
                List<String> data = this.split(cert);
                for (String line : data) {
                    writer.write(line);
                    writer.write(NEW_LINE);
                }
                writer.write("-----END CERTIFICATE-----");
                writer.write(NEW_LINE);
                writer.flush();
            }
            else {
                System.err.println("The input BufferedWriter is null.  "
                        + "Unable to output the certificate.");
            }
        }
        else {
            System.err.println("The input X509Certificate is null.  "
                    + "Unable to output the certificate.");
        }
    }
    
    
    public void exportToIndividualFiles(
            String keystoreFile,
            String keystorePassword,
            String outputPath) {
        
        int  counter = 0;
        Path p       = null;
        
        if ((outputPath != null) && (!outputPath.isEmpty())) {
            p = Paths.get(outputPath);
            if ((!Files.exists(p)) && (!Files.isDirectory(p))) {
                p = Paths.get(System.getProperty("java.io.tmpdir"));
            }
        }
        else {
            p = Paths.get(System.getProperty("java.io.tmpdir"));
        }
        
        System.out.println("Writing output files to => [ "
                + p.toString()
                + " ].");
        
        if ((keystoreFile != null) && (!keystoreFile.isEmpty())) { 
            try (InputStream keyStoreInputStream = 
                    new FileInputStream(keystoreFile)) {
                
                KeyStore keyStore = KeyStore.getInstance("jks");
                keyStore.load(
                        keyStoreInputStream, 
                        keystorePassword.toCharArray());        
                Enumeration<String> aliases = keyStore.aliases();
                
                while (aliases.hasMoreElements()) {
                    
                    String alias = aliases.nextElement();
                    X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
                    Path filePath = Paths.get(
                            p.toString(), 
                            (alias.trim().toLowerCase()+PEM_FILE_EXTENSION));
                    System.out.println("Writing => [ "
                            + filePath.toString()
                            + " ].");
                    try (BufferedWriter writer = 
                            Files.newBufferedWriter(
                                    filePath, 
                                    Charset.forName("UTF-8"))) {
                        writeCertificate(cert, writer);
                    }
                    catch (IOException ioe) {
                        System.err.println("Unexpected IOException raised while "
                                + "attempting to write to the target output "
                                + "file [ "
                                + filePath.toString()
                                + " ].  Error message => [ "
                                + ioe.getMessage()
                                + " ].");
                    }    
                    counter++;
                }
                System.out.println("Processed [ "
                        + counter
                        + " ] certificates.");
            }
            catch (CertificateException ce) {
                System.err.println("CertificateException encountered "
                        + "while attempting load the target key store  "
                        + "file.  File name => [ "
                        + keystoreFile
                        + " ], error message => [ "
                        + ce.getMessage()
                        + " ].");    
            }
            catch (NoSuchAlgorithmException nsae) {
                System.err.println("NoSuchAlgorithmException encountered "
                        + "while attempting load the target key store  "
                        + "file.  File name => [ "
                        + keystoreFile
                        + " ], error message => [ "
                        + nsae.getMessage()
                        + " ].");                    
            }
            catch (KeyStoreException ke) {
                System.err.println("KeyStoreException encountered while "
                        + " attempting to read from the target trust store "
                        + "file.  File name => [ "
                        + keystoreFile
                        + " ], error message => [ "
                        + ke.getMessage()
                        + " ].");
            }
            catch (FileNotFoundException fnfe) {
                System.err.println("FileNotFoundException encountered while "
                        + "attempting to read the target trust store file.  "
                        + "File name => [ "
                        + keystoreFile
                        + " ], error message => [ "
                        + fnfe.getMessage()
                        + " ].");
            }
            catch (IOException nsae) {
                System.err.println("IOException encountered "
                        + "while attempting load the target key store  "
                        + "file.  File name => [ "
                        + keystoreFile
                        + " ], error message => [ "
                        + nsae.getMessage()
                        + " ].");                    
            }
        }
        else {
            System.err.println("Target keystore location not provided.");
        }
    }
    
    /**
     * Default constructor driving execution.
     * 
     * @param keystoreFile The path to the KeyStore file.
     * @param keystorePassword The password associated with the KeyStore file.
     * @param outputFile The output file.
     */
    public void exportToSingleFile (
            String keystoreFile,
            String keystorePassword,
            String outputFile) {
    
        String alias   = null;
        int    counter = 0;
        
        if ((outputFile != null) && (!outputFile.isEmpty())) {
            Path outputPath = Paths.get(outputFile);
            if ((keystoreFile != null) && (!keystoreFile.isEmpty())) { 
                
                try (InputStream keyStoreInputStream = 
                        new FileInputStream(keystoreFile);
                    BufferedWriter writer = Files.newBufferedWriter(
                            outputPath,
                            Charset.forName("UTF-8"))) {
                
                        KeyStore keyStore = KeyStore.getInstance("jks");
                        keyStore.load(keyStoreInputStream, 
                                    keystorePassword.toCharArray());        
                        Enumeration<String> aliases = keyStore.aliases();
                        
                        while (aliases.hasMoreElements()) {
                            alias = aliases.nextElement();
                            counter++;
                            X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
                            writeCertificate(cert, writer);
                        }
                        System.out.println("Processed [ "
                                + counter
                                + " ] certificates.");
                }
                catch (NoSuchAlgorithmException nsae) {
                    System.err.println("NoSuchAlgorithmException encountered "
                            + "while attempting load the target key store  "
                            + "file.  File name [ "
                            + keystoreFile
                            + " ], error message => [ "
                            + nsae.getMessage()
                            + " ].");                    
                }
                catch (CertificateEncodingException cee) {
                    System.err.println("CertificateEncodingException encountered "
                            + "while attempting to convert the target certificate  "
                            + "into a byte array.  Alias [ "
                            + alias
                            + " ], file name [ "
                            + keystoreFile
                            + " ], error message => [ "
                            + cee.getMessage()
                            + " ].");    
                }
                catch (CertificateException ce) {
                    System.err.println("CertificateException encountered "
                            + "while attempting load the target key store  "
                            + "file.  File name [ "
                            + keystoreFile
                            + " ], error message [ "
                            + ce.getMessage()
                            + " ].");    
                }
                catch (FileNotFoundException fnfe) {
                    System.err.println("FileNotFoundException encountered while "
                            + "attempting to read the target trust store file.  "
                            + "File name [ "
                            + keystoreFile
                            + " ], error message [ "
                            + fnfe.getMessage()
                            + " ].");
                }
                catch (KeyStoreException kse) {
                    System.err.println("KeyStoreException encountered while "
                            + " attempting to read from the target trust store "
                            + "file.  File name [ "
                            + keystoreFile
                            + " ], error message [ "
                            + kse.getMessage()
                            + " ].");
                }
                catch (IOException nsae) {
                    System.err.println("IOException encountered "
                            + "while attempting load the target key store  "
                            + "file.  File name [ "
                            + keystoreFile
                            + " ], error message [ "
                            + nsae.getMessage()
                            + " ].");                    
                }
            }
            else {
                System.err.println("Target keystore location not provided.");
            }
        }
        else {
            System.err.println("Target output file not specified.");
        }
    }
    
    
    /**
     * Main method is for parsing the command line arguments.
     * 
     * @param args
     */
    public static void main(String[] args) {
        
        String  keyStoreFileName = null;
        String  outputFile       = null;
        boolean singleFile       = false;
        
        // Set up the command line options
        Options opt = new Options(args, 0);
        opt.getSet().addOption("keystore", Separator.EQUALS, 
                Multiplicity.ONCE);
        opt.getSet().addOption("output", Separator.EQUALS, 
                Multiplicity.ONCE);
        opt.getSet().addOption("singleFile", Multiplicity.ZERO_OR_ONE);
        opt.getSet().addOption("h", Multiplicity.ZERO_OR_ONE);
        opt.getSet().addOption("help", Multiplicity.ZERO_OR_ONE);
        
        // Make sure the options make sense
        if (!opt.check(true, false)) {
            if (opt.getSet().isSet("h") || opt.getSet().isSet("help")) {
                System.out.println(ExportJKSFile.HELP_STRING);
                System.out.println("");
                System.out.println(ExportJKSFile.USAGE_STRING);
                System.exit(0);
            }
            else {
                System.out.println(ExportJKSFile.USAGE_STRING);
            }
            System.exit(1);
        }

        if (opt.getSet().isSet("singleFile")) {
            singleFile = true;
        }
        
        // Retrieve the command line parameters
        if (opt.getSet().isSet("keystore") && opt.getSet().isSet("output")) {
            keyStoreFileName = 
                    opt.getSet().getOption("keystore").getResultValue(0);
            outputFile = 
                    opt.getSet().getOption("output").getResultValue(0);
        }
        else {
            System.out.println(ExportJKSFile.HELP_STRING);
            System.out.println("");
            System.out.println(ExportJKSFile.USAGE_STRING);
            System.exit(1);
        }
        
            
        // Output the command line parameters for debugging purposes
        if (ExportJKSFile.DEBUG) {
            System.out.println("===== DEBUG INFO =====");
            System.out.println("Key Store    : " + keyStoreFileName);
            System.out.println("Output       : " + outputFile);
            System.out.println("===== DEBUG INFO =====");
        }
        
        try {
            
            // Prompt the user for the password for the keystore.
            System.out.print("Keystore password>  ");
            String keyStorePassword = (new BufferedReader(
                    new InputStreamReader(System.in))).readLine();
    
            ExportJKSFile exporter = new ExportJKSFile();
            if (singleFile == true) {
                exporter.exportToSingleFile(
                        keyStoreFileName, 
                        keyStorePassword, 
                        outputFile);
            }
            else {
                exporter.exportToIndividualFiles(
                        keyStoreFileName, 
                        keyStorePassword, 
                        outputFile);
            }
        }
        catch (IOException ioe) {
            System.err.println(
                    "Unexpected error reading password from "
                    + "command line.  Error encountered [ "
                    + ioe.getMessage()
                    + " ].");
        }

        System.out.println("Keystore dump complete!");
    }
}
