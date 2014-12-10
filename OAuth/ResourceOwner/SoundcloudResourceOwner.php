<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware.Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use Symfony\Component\OptionsResolver\OptionsResolverInterface;

/**
 * SoundcloudResourceOwner
 *
 * @author Anthony AHMED <antho.ahmed@gmail.com>
 */
class SoundcloudResourceOwner extends GenericOAuth2ResourceOwner
{
	/**
     * {@inheritDoc}
     */
    protected $paths = array(
    	'identifier' => 'id',
        'nickname'   => 'username',
        'realname'   => 'full_name',
    );

    /**
     * @param array $accessToken
     * @param array $extraParameters
     * @return \HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface
     */
    public function getUserInformation(array $accessToken, array $extraParameters = array())
    {
        if ($this->options['use_bearer_authorization']) {
            $content = $this->httpRequest($this->normalizeUrl($this->options['infos_url']), null, array('Authorization: Bearer '.$accessToken['access_token']));
        } else {
            $content = $this->doGetUserInformationRequest($this->normalizeUrl($this->options['infos_url'], array('oauth_token' => $accessToken['access_token'])));
        }

        $response = $this->getUserResponse();
        $response->setResponse($content->getContent());
        $response->setResourceOwner($this);
        $response->setOAuthToken(new OAuthToken($accessToken));

        return $response;
    }

    /**
     * {@inheritDoc}
     */
    protected function configureOptions(OptionsResolverInterface $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults(array(
            'access_token_url'         => 'https://api.soundcloud.com/oauth2/token',
            'authorization_url'        => 'https://soundcloud.com/connect',
            'infos_url'                => 'https://api.soundcloud.com/me.json',

            'use_bearer_authorization' => false,
            'scope'                    => 'non-expiring',
        ));
    }
}
