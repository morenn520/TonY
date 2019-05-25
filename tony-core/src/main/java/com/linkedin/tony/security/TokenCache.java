/**
 * Copyright 2018 LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
 * See LICENSE in the project root for license information.
 */
package com.linkedin.tony.security;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.token.Token;

/**
 * This class provides user facing APIs for transferring secrets from
 * the job client to the tasks.
 * The secrets can be stored just before submission of jobs and read during
 * the task execution.  
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public class TokenCache {
  
  private static final Log LOG = LogFactory.getLog(TokenCache.class);

  private TokenCache() {
      // Prevent instantiation
  }

  /**
   * Convenience method to obtain delegation tokens from namenodes 
   * corresponding to the paths passed.
   * @param credentials
   * @param ps array of paths
   * @param conf configuration
   * @throws IOException
   */
  public static void obtainTokensForNamenodes(Credentials credentials,
      Path[] ps, Configuration conf, String renewer) throws IOException {
    Set<FileSystem> fsSet = new HashSet<FileSystem>();
    for (Path p : ps) {
      fsSet.add(p.getFileSystem(conf));
    }
    for (FileSystem fs : fsSet) {
      obtainTokensForNamenodesInternal(fs, credentials, conf, renewer);
    }
  }

  /**
   * get delegation token for a specific FS
   * @param fs
   * @param credentials
   * @param p
   * @param conf
   * @throws IOException
   */
  static void obtainTokensForNamenodesInternal(FileSystem fs,
      Credentials credentials, Configuration conf, String renewer) throws IOException {
    final Token<?>[] tokens = fs.addDelegationTokens(renewer,
                                                     credentials);
    if (tokens != null) {
      for (Token<?> token : tokens) {
        LOG.info("Got dt for " + fs.getUri() + "; " + token);
      }
    }
  }

}
